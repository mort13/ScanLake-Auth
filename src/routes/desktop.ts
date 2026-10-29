import type { Context, MiddlewareHandler } from 'hono'
import { html } from 'hono/html'
import type { AppEnv, Env, Me } from '../types'
import { isAllowedClientId, isAllowedRedirectUri } from '../desktop/redirect'
import { isValidChallenge, isValidVerifier, verifyPkce } from '../services/pkce'
import { createBearerSession, nowS, randomToken, readSession, sha256Hex } from '../services/session'
import { loadMe } from '../services/accounts'

// Desktop / native-app login: RFC 8252 loopback redirect + RFC 7636 PKCE (S256).
// The browser half reuses the web login (cookie session); the app gets a bearer token.

const CODE_TTL_S = 120
const CODE_RE = /^[A-Za-z0-9_-]{43}$/
// Echoed back to the app unchanged: 1-256 printable ASCII characters, no spaces
const STATE_RE = /^[\x21-\x7e]{1,256}$/

interface AuthorizeRequest {
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
}

type ParsedAuthorize =
  | { error: null; request: AuthorizeRequest }
  // Sent back to the app's redirect URI
  | { error: 'invalid_request'; redirectUri: string; state: string | undefined }
  // Unknown client or redirect URI: shown as a page, never redirected to
  | { error: 'invalid_link' }

/**
 * Headers for every /desktop/* response: never cached, never framed, no Referer to
 * the app. `same-origin` rather than `no-referrer`: with `no-referrer` browsers send
 * `Origin: null` on the Allow/Deny form POST, which the Origin guard would refuse.
 */
export const desktopHeaders: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next()
  c.header('Cache-Control', 'no-store')
  c.header('X-Frame-Options', 'DENY')
  c.header(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  )
  c.header('Referrer-Policy', 'same-origin')
}

/**
 * `GET /desktop/authorize?response_type=code&client_id&redirect_uri&state&code_challenge&code_challenge_method=S256`:
 * opened by the desktop app in the system browser. Logs in through the web login if
 * needed, then asks the user to allow the app.
 */
export async function authorizePageRoute(c: Context<AppEnv>) {
  const parsed = parseAuthorize(c.req.query())
  if (parsed.error === 'invalid_link') return invalidLinkPage(c)
  if (parsed.error) return redirectToApp(c, parsed.redirectUri, { error: parsed.error, state: parsed.state }, 302)

  const me = await currentWebUser(c)
  if (!me) return redirectToLogin(c, parsed.request, 302)
  return c.html(confirmPage(parsed.request, me))
}

/** `POST /desktop/authorize` (form from the confirmation page): Allow issues a code, Deny tells the app. */
export async function authorizeDecisionRoute(c: Context<AppEnv>) {
  const form = await readForm(c)
  const parsed = parseAuthorize(form)
  if (parsed.error === 'invalid_link') return invalidLinkPage(c)
  if (parsed.error) return redirectToApp(c, parsed.redirectUri, { error: parsed.error, state: parsed.state }, 303)

  const { request } = parsed
  if (form.decision !== 'allow') {
    return redirectToApp(c, request.redirectUri, { error: 'access_denied', state: request.state }, 303)
  }

  // Logged out in another tab since the page was shown
  const me = await currentWebUser(c)
  if (!me) return redirectToLogin(c, request, 303)
  if (!(await withinRateLimit(c.env, `authorize:${me.discord.id}`))) {
    return c.text('Too many sign-in attempts. Please wait a minute and try again.', 429)
  }

  const code = randomToken()
  const now = nowS()
  await c.env.AUTH_DB.prepare(
    `INSERT INTO desktop_codes (code_hash, discord_id, client_id, redirect_uri, code_challenge, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(await sha256Hex(code), me.discord.id, request.clientId, request.redirectUri, request.codeChallenge, now, now + CODE_TTL_S)
    .run()
  return redirectToApp(c, request.redirectUri, { code, state: request.state }, 303)
}

/**
 * `POST /desktop/token` (form: grant_type=authorization_code, code, code_verifier, redirect_uri, client_id):
 * exchanges a code for a bearer token. Errors are 400 `{ error: 'invalid_request' | 'invalid_grant' }`.
 */
export async function tokenRoute(c: Context<AppEnv>) {
  c.header('Pragma', 'no-cache')
  if (!(await withinRateLimit(c.env, `token:${c.req.header('CF-Connecting-IP') ?? 'unknown'}`))) {
    return c.json({ error: 'rate_limited' }, 429)
  }

  const form = await readForm(c)
  if (form.grant_type !== 'authorization_code' || typeof form.code !== 'string' || !CODE_RE.test(form.code)) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  // Consumed before anything else is checked, so a code is single-use even when the attempt fails
  const row = await c.env.AUTH_DB.prepare(
    `DELETE FROM desktop_codes WHERE code_hash = ?
     RETURNING discord_id, client_id, redirect_uri, code_challenge, expires_at`,
  )
    .bind(await sha256Hex(form.code))
    .first<{ discord_id: string; client_id: string; redirect_uri: string; code_challenge: string; expires_at: number }>()

  const { code_verifier: verifier, redirect_uri: redirectUri, client_id: clientId } = form
  if (!isValidVerifier(verifier) || typeof redirectUri !== 'string' || typeof clientId !== 'string') {
    return c.json({ error: 'invalid_request' }, 400)
  }
  if (
    !row ||
    row.expires_at <= nowS() ||
    row.redirect_uri !== redirectUri ||
    row.client_id !== clientId ||
    !(await verifyPkce(verifier, row.code_challenge))
  ) {
    return c.json({ error: 'invalid_grant' }, 400)
  }

  const { token, expiresIn } = await createBearerSession(c.env.AUTH_DB, row.discord_id, row.client_id)
  return c.json({ access_token: token, token_type: 'Bearer', expires_in: expiresIn })
}

/** Checks the authorize parameters; a bad client or redirect URI is never redirected to (RFC 6749 §4.1.2.1). */
function parseAuthorize(params: Record<string, unknown>): ParsedAuthorize {
  const { client_id: clientId, redirect_uri: redirectUri } = params
  if (!isAllowedClientId(clientId) || !isAllowedRedirectUri(redirectUri)) return { error: 'invalid_link' }

  const state = typeof params.state === 'string' && STATE_RE.test(params.state) ? params.state : undefined
  const challenge = params.code_challenge
  if (
    params.response_type !== 'code' ||
    !state ||
    params.code_challenge_method !== 'S256' ||
    !isValidChallenge(challenge)
  ) {
    return { error: 'invalid_request', redirectUri, state }
  }
  return { error: null, request: { clientId, redirectUri, state, codeChallenge: challenge } }
}

/** The account of the browser's web (cookie) session; a bearer token never authorizes a new app. */
async function currentWebUser(c: Context<AppEnv>): Promise<Me | null> {
  const session = await readSession(c)
  if (!session || session.kind !== 'cookie') return null
  return loadMe(c.env.AUTH_DB, session.discordId)
}

async function readForm(c: Context<AppEnv>): Promise<Record<string, unknown>> {
  try {
    return await c.req.parseBody()
  } catch {
    return {}
  }
}

/** True unless the optional rate limiter says `key` is over its limit. */
async function withinRateLimit(env: Env, key: string): Promise<boolean> {
  if (!env.DESKTOP_RATE_LIMIT) return true
  const { success } = await env.DESKTOP_RATE_LIMIT.limit({ key })
  return success
}

function authorizeUrl(env: Env, request: AuthorizeRequest): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    state: request.state,
    code_challenge: request.codeChallenge,
    code_challenge_method: 'S256',
  })
  return `${env.PUBLIC_URL}/desktop/authorize?${params}`
}

/** The web login, coming back to the same authorize request afterwards. */
function redirectToLogin(c: Context<AppEnv>, request: AuthorizeRequest, status: 302 | 303) {
  const returnTo = authorizeUrl(c.env, request)
  return c.redirect(`${c.env.PUBLIC_URL}/login?return_to=${encodeURIComponent(returnTo)}`, status)
}

/** Redirects to the app's loopback listener (which never has a query of its own). */
function redirectToApp(
  c: Context<AppEnv>,
  redirectUri: string,
  params: Record<string, string | undefined>,
  status: 302 | 303,
) {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) if (value !== undefined) query.set(key, value)
  return c.redirect(`${redirectUri}?${query}`, status)
}

function invalidLinkPage(c: Context<AppEnv>) {
  return c.html(
    layout(
      'Invalid sign-in link',
      html`<h1>This sign-in link is invalid</h1>
        <p>Start the sign-in again from ScanLake Desktop.</p>`,
    ),
    400,
  )
}

function confirmPage(request: AuthorizeRequest, me: Me) {
  const { globalName, username } = me.discord
  const who = globalName ? html`${globalName} (@${username})` : html`@${username}`
  return layout(
    'Sign in to ScanLake Desktop',
    html`<h1>Sign in to ScanLake Desktop as ${who}?</h1>
      <p>
        ScanLake Desktop on this computer will be able to read and change your ScanLake account: linked IDs,
        Capture profile and Discord link. Only allow this if you just started signing in from ScanLake Desktop.
      </p>
      <form method="post" action="/desktop/authorize">
        <input type="hidden" name="response_type" value="code" />
        <input type="hidden" name="client_id" value="${request.clientId}" />
        <input type="hidden" name="redirect_uri" value="${request.redirectUri}" />
        <input type="hidden" name="state" value="${request.state}" />
        <input type="hidden" name="code_challenge" value="${request.codeChallenge}" />
        <input type="hidden" name="code_challenge_method" value="S256" />
        <button type="submit" name="decision" value="allow">Allow</button>
        <button type="submit" name="decision" value="deny" class="secondary">Deny</button>
      </form>`,
  )
}

function layout(title: string, body: ReturnType<typeof html>) {
  return html`<!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${title}</title>
        <style>
          :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
          body { margin: 0; min-height: 100vh; display: grid; place-items: center; }
          main { max-width: 28rem; padding: 2rem 1rem; }
          h1 { font-size: 1.25rem; overflow-wrap: anywhere; }
          p { line-height: 1.5; }
          button { font: inherit; padding: 0.5rem 1.25rem; margin-right: 0.5rem; border-radius: 6px;
            border: 1px solid #5865f2; background: #5865f2; color: #fff; cursor: pointer; }
          button.secondary { background: transparent; color: inherit; border-color: currentColor; }
        </style>
      </head>
      <body>
        <main>${body}</main>
      </body>
    </html>`
}
