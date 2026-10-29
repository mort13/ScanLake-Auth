import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'
import { isAllowedOrigin } from '../src/origins'
import { sha256Hex } from '../src/services/session'
import {
  BASE,
  CLIENT_ID,
  DISCORD_ID,
  REDIRECT_URI,
  STATE,
  authorizeQuery,
  bearer,
  call,
  cookieHeader,
  exchange,
  issueCode,
  postDecision,
  resetDb,
  seedAccount,
  seedSession,
  sessionRow,
  tokenFields,
} from './helpers'

beforeEach(async () => {
  await resetDb()
  await seedAccount()
})

function location(res: Response): URL {
  return new URL(res.headers.get('Location')!)
}

function expectAntiFraming(res: Response) {
  expect(res.headers.get('Cache-Control')).toBe('no-store')
  expect(res.headers.get('X-Frame-Options')).toBe('DENY')
  expect(res.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'")
  expect(res.headers.get('Referrer-Policy')).toBe('same-origin')
}

describe('GET /desktop/authorize', () => {
  it('sends a logged-out browser to the web login and back', async () => {
    const res = await call(`/desktop/authorize?${authorizeQuery()}`)
    expect(res.status).toBe(302)
    const loginUrl = location(res)
    expect(`${loginUrl.origin}${loginUrl.pathname}`).toBe(`${BASE}/login`)

    const returnTo = loginUrl.searchParams.get('return_to')!
    expect(returnTo).toBe(`${BASE}/desktop/authorize?${authorizeQuery()}`)
    expect(isAllowedOrigin(returnTo, env)).toBe(true)
  })

  it('shows the confirmation page with escaped names and anti-framing headers', async () => {
    await resetDb()
    await seedAccount(DISCORD_ID, { username: 'a&b"<i>', globalName: '<script>alert(1)</script>' })
    const cookie = await seedSession()

    const res = await call(`/desktop/authorize?${authorizeQuery()}`, { headers: { Cookie: cookieHeader(cookie) } })
    expect(res.status).toBe(200)
    expectAntiFraming(res)
    const body = await res.text()
    expect(body).toContain('Sign in to ScanLake Desktop as &lt;script&gt;alert(1)&lt;/script&gt; (@a&amp;b&quot;&lt;i&gt;)?')
    expect(body).not.toContain('<script>')
    expect(body).not.toContain('<i>')
    expect(body).toContain('<form method="post" action="/desktop/authorize">')
    expect(body).toContain(`value="${STATE}"`)
  })

  it('falls back to @username without a display name', async () => {
    await resetDb()
    await seedAccount(DISCORD_ID, { username: 'miner', globalName: null })
    const cookie = await seedSession()
    const res = await call(`/desktop/authorize?${authorizeQuery()}`, { headers: { Cookie: cookieHeader(cookie) } })
    expect(await res.text()).toContain('Sign in to ScanLake Desktop as @miner?')
  })

  it('escapes the state in the hidden form field', async () => {
    const cookie = await seedSession()
    const state = '"><script>x</script>'
    const res = await call(`/desktop/authorize?${authorizeQuery({ state })}`, { headers: { Cookie: cookieHeader(cookie) } })
    const body = await res.text()
    expect(body).toContain('value="&quot;&gt;&lt;script&gt;x&lt;/script&gt;"')
    expect(body).not.toContain('<script>')
  })

  it('does not accept a desktop bearer token as the browser session', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop')
    const res = await call(`/desktop/authorize?${authorizeQuery()}`, { headers: bearer(token) })
    expect(res.status).toBe(302)
    expect(location(res).pathname).toBe('/login')
  })

  it.each([
    ['unknown client_id', { client_id: 'other-app' }],
    ['missing client_id', { client_id: null }],
    ['localhost redirect_uri', { redirect_uri: 'http://localhost:53682/callback' }],
    ['https redirect_uri', { redirect_uri: 'https://evil.example/callback' }],
    ['redirect_uri with query', { redirect_uri: `${REDIRECT_URI}?x=1` }],
    ['missing redirect_uri', { redirect_uri: null }],
  ])('shows an error page and never redirects for %s', async (_label, overrides) => {
    const res = await call(`/desktop/authorize?${authorizeQuery(overrides)}`)
    expect(res.status).toBe(400)
    expect(res.headers.get('Location')).toBeNull()
    expectAntiFraming(res)
    expect(await res.text()).toContain('This sign-in link is invalid')
  })

  it.each([
    ['response_type', { response_type: 'token' }],
    ['missing code_challenge', { code_challenge: null }],
    ['short code_challenge', { code_challenge: 'abc' }],
    ['plain method', { code_challenge_method: 'plain' }],
    ['missing method', { code_challenge_method: null }],
  ])('redirects invalid_request with state for a bad %s', async (_label, overrides) => {
    const res = await call(`/desktop/authorize?${authorizeQuery(overrides)}`)
    expect(res.status).toBe(302)
    const url = location(res)
    expect(`${url.origin}${url.pathname}`).toBe(REDIRECT_URI)
    expect(url.searchParams.get('error')).toBe('invalid_request')
    expect(url.searchParams.get('state')).toBe(STATE)
  })

  it('redirects invalid_request without state when state is missing', async () => {
    const res = await call(`/desktop/authorize?${authorizeQuery({ state: null })}`)
    const url = location(res)
    expect(url.searchParams.get('error')).toBe('invalid_request')
    expect(url.searchParams.has('state')).toBe(false)
  })
})

describe('POST /desktop/authorize', () => {
  it('Allow issues a hashed one-time code bound to the request', async () => {
    const cookie = await seedSession()
    const res = await postDecision(cookie)
    expect(res.status).toBe(303)
    expectAntiFraming(res)
    const url = location(res)
    expect(`${url.origin}${url.pathname}`).toBe(REDIRECT_URI)
    expect(url.searchParams.get('state')).toBe(STATE)
    const code = url.searchParams.get('code')!
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const row = await env.AUTH_DB.prepare('SELECT * FROM desktop_codes').first<Record<string, unknown>>()
    expect(row).toMatchObject({
      code_hash: await sha256Hex(code),
      discord_id: DISCORD_ID,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    })
    expect((row!.expires_at as number) - (row!.created_at as number)).toBe(120)
  })

  it('works with the IPv6 loopback redirect', async () => {
    const cookie = await seedSession()
    const redirectUri = 'http://[::1]:49152/callback'
    const code = await issueCode(cookie, { redirect_uri: redirectUri })
    const res = await exchange(tokenFields(code, { redirect_uri: redirectUri }))
    expect(res.status).toBe(200)
  })

  it('Deny redirects access_denied and issues nothing', async () => {
    const cookie = await seedSession()
    const res = await postDecision(cookie, { decision: 'deny' })
    expect(res.status).toBe(303)
    const url = location(res)
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('state')).toBe(STATE)
    expect(url.searchParams.has('code')).toBe(false)
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(0)
  })

  it('re-validates the parameters', async () => {
    const cookie = await seedSession()
    const bad = await postDecision(cookie, { redirect_uri: 'http://localhost:53682/callback' })
    expect(bad.status).toBe(400)
    expect(bad.headers.get('Location')).toBeNull()

    const plain = await postDecision(cookie, { code_challenge_method: 'plain' })
    expect(plain.status).toBe(303)
    expect(location(plain).searchParams.get('error')).toBe('invalid_request')
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(0)
  })

  it('needs a cookie session', async () => {
    const res = await postDecision(null)
    expect(res.status).toBe(303)
    expect(location(res).pathname).toBe('/login')
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(0)
  })

  it('is refused without a ScanLake Origin (CSRF)', async () => {
    const cookie = await seedSession()
    expect((await postDecision(cookie, {}, null)).status).toBe(403)
    expect((await postDecision(cookie, {}, 'https://evil.example')).status).toBe(403)
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(0)
  })
})

describe('POST /desktop/token', () => {
  it('exchanges a code for a desktop bearer session', async () => {
    const code = await issueCode(await seedSession())
    // No Origin header, like a desktop HTTP client
    const res = await exchange(tokenFields(code))
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
    const body = await res.json<{ access_token: string; token_type: string; expires_in: number }>()
    expect(body.token_type).toBe('Bearer')
    expect(body.expires_in).toBe(90 * 86400)
    expect(body.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/)

    expect(await sessionRow(body.access_token)).toMatchObject({ discord_id: DISCORD_ID, kind: 'desktop', client: CLIENT_ID })
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(0)

    const me = await call('/api/me', { headers: bearer(body.access_token) })
    expect(me.status).toBe(200)
    expect((await me.json<{ discord: { id: string } }>()).discord.id).toBe(DISCORD_ID)
  })

  it('accepts a code only once', async () => {
    const code = await issueCode(await seedSession())
    expect((await exchange(tokenFields(code))).status).toBe(200)
    const again = await exchange(tokenFields(code))
    expect(again.status).toBe(400)
    expect(await again.json()).toEqual({ error: 'invalid_grant' })
  })

  it('burns the code on a wrong verifier', async () => {
    const code = await issueCode(await seedSession())
    const wrong = await exchange(tokenFields(code, { code_verifier: 'x'.repeat(43) }))
    expect(wrong.status).toBe(400)
    expect(await wrong.json()).toEqual({ error: 'invalid_grant' })
    // The right verifier no longer helps
    const right = await exchange(tokenFields(code))
    expect(await right.json()).toEqual({ error: 'invalid_grant' })
  })

  it('refuses an expired code', async () => {
    const code = await issueCode(await seedSession())
    await env.AUTH_DB.prepare('UPDATE desktop_codes SET expires_at = expires_at - 121').run()
    const res = await exchange(tokenFields(code))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_grant' })
  })

  it.each([
    ['another port', { redirect_uri: 'http://127.0.0.1:53683/callback' }],
    ['IPv6 instead of IPv4', { redirect_uri: 'http://[::1]:53682/callback' }],
    ['another client_id', { client_id: 'other-app' }],
  ])('refuses a %s mismatch', async (_label, overrides) => {
    const code = await issueCode(await seedSession())
    const res = await exchange(tokenFields(code, overrides))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_grant' })
    expect((await exchange(tokenFields(code))).status).toBe(400)
  })

  it('refuses an unknown code', async () => {
    const res = await exchange(tokenFields('A'.repeat(43)))
    expect(await res.json()).toEqual({ error: 'invalid_grant' })
  })

  it.each([
    ['grant_type', { grant_type: 'refresh_token' }],
    ['missing grant_type', { grant_type: null }],
    ['missing code', { code: null }],
    ['malformed code', { code: 'short' }],
  ])('rejects a bad %s as invalid_request', async (_label, overrides) => {
    const code = await issueCode(await seedSession())
    const res = await exchange(tokenFields(code, overrides))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_request' })
  })

  it.each([
    ['missing verifier', { code_verifier: null }],
    ['short verifier', { code_verifier: 'a'.repeat(42) }],
    ['missing redirect_uri', { redirect_uri: null }],
    ['missing client_id', { client_id: null }],
  ])('rejects a %s as invalid_request and burns the code', async (_label, overrides) => {
    const code = await issueCode(await seedSession())
    const res = await exchange(tokenFields(code, overrides))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_request' })
    expect((await exchange(tokenFields(code))).status).toBe(400)
  })

  it('rejects a JSON body', async () => {
    const code = await issueCode(await seedSession())
    const res = await call('/desktop/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tokenFields(code)),
    })
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_request' })
  })

  it('does not need an Origin, and ignores a foreign one', async () => {
    const code = await issueCode(await seedSession())
    const res = await exchange(tokenFields(code), { Origin: 'https://evil.example' })
    expect(res.status).toBe(200)
  })
})
