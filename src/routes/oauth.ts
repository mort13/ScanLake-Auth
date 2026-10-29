import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import type { AppEnv } from '../types'
import { isAllowedOrigin } from '../origins'
import { authorizeUrl, exchangeCode, fetchUser, revokeToken } from '../services/discord'
import { createSession, endSession, randomToken } from '../services/session'
import { upsertAccount } from '../services/accounts'

// Holds the OAuth state and where to send the user back, only for the round trip to Discord
const STATE_COOKIE = 'sl_oauth'
const STATE_TTL_S = 600

interface OAuthState {
  state: string
  returnTo: string
}

/** `GET /login?return_to=<app url>`: starts the Discord login. */
export async function loginRoute(c: Context<AppEnv>) {
  if (!c.env.DISCORD_CLIENT_ID || !c.env.DISCORD_CLIENT_SECRET) {
    return c.text('Discord login is not configured.', 503)
  }
  const returnTo = c.req.query('return_to') ?? ''
  if (!isAllowedOrigin(returnTo, c.env)) {
    return c.text('return_to must be a ScanLake app URL.', 400)
  }

  const saved: OAuthState = { state: randomToken(16), returnTo }
  setCookie(c, STATE_COOKIE, JSON.stringify(saved), {
    path: '/callback',
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: STATE_TTL_S,
  })
  return c.redirect(authorizeUrl(c.env, saved.state), 302)
}

/** `GET /callback?code&state`: Discord sends the user back here. */
export async function callbackRoute(c: Context<AppEnv>) {
  const saved = readState(c)
  deleteCookie(c, STATE_COOKIE, { path: '/callback', secure: true })

  const { code, state, error } = c.req.query()
  if (!saved || !state || state !== saved.state || !isAllowedOrigin(saved.returnTo, c.env)) {
    return c.text('This login link expired or is invalid. Please start the login again.', 400)
  }
  // The user cancelled on Discord's page
  if (error || !code) return c.redirect(saved.returnTo, 302)

  try {
    const accessToken = await exchangeCode(c.env, code)
    const user = await fetchUser(accessToken)
    c.executionCtx.waitUntil(revokeToken(c.env, accessToken).catch(() => {}))

    await upsertAccount(c.env.AUTH_DB, user)
    await createSession(c, user.id)
  } catch (err) {
    console.error('[callback] login failed:', err)
    return c.text('Discord login failed. Please try again.', 502)
  }
  return c.redirect(saved.returnTo, 302)
}

/** `POST /logout`: ends the session in every ScanLake app. */
export async function logoutRoute(c: Context<AppEnv>) {
  await endSession(c)
  return c.body(null, 204)
}

function readState(c: Context<AppEnv>): OAuthState | null {
  const raw = getCookie(c, STATE_COOKIE)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<OAuthState>
    if (typeof parsed.state !== 'string' || typeof parsed.returnTo !== 'string') return null
    return { state: parsed.state, returnTo: parsed.returnTo }
  } catch {
    return null
  }
}
