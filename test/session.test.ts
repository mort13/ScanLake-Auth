import { env, exports } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'
import { deleteExpiredSessions, nowS } from '../src/services/session'
import {
  APP_ORIGIN,
  DISCORD_ID,
  bearer,
  call,
  cookieHeader,
  issueCode,
  resetDb,
  seedAccount,
  seedSession,
  sessionRow,
} from './helpers'

const OTHER_ID = '100000000000000002'
const USER_ID = '0b5e3f9a-3c1d-4e2f-9a8b-7c6d5e4f3a2b'

beforeEach(async () => {
  await resetDb()
  await seedAccount()
  await seedAccount(OTHER_ID, { username: 'other', globalName: 'Other' })
})

async function meId(res: Response): Promise<string> {
  return (await res.json<{ discord: { id: string } }>()).discord.id
}

function linkUserId(headers: Record<string, string>) {
  return call('/api/me/user-ids', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ userId: USER_ID }),
  })
}

describe('bearer sessions', () => {
  it('GET /api/me works with a desktop bearer token', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop')
    const res = await call('/api/me', { headers: bearer(token) })
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
    expect(await meId(res)).toBe(DISCORD_ID)
  })

  it('accepts the scheme in any case', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop')
    const res = await call('/api/me', { headers: { Authorization: `bearer ${token}` } })
    expect(res.status).toBe(200)
  })

  it('ignores the cookie when an Authorization header is sent', async () => {
    const desktop = await seedSession(DISCORD_ID, 'desktop')
    const cookie = await seedSession(OTHER_ID, 'cookie')

    const both = await call('/api/me', { headers: { ...bearer(desktop), Cookie: cookieHeader(cookie) } })
    expect(await meId(both)).toBe(DISCORD_ID)

    const badBearer = await call('/api/me', {
      headers: { Authorization: 'Bearer nope', Cookie: cookieHeader(cookie) },
    })
    expect(badBearer.status).toBe(401)
  })

  it.each([
    ['empty header', ''],
    ['scheme only', 'Bearer'],
    ['scheme and space', 'Bearer '],
    ['short token', 'Bearer abc'],
    ['44-char token', `Bearer ${'a'.repeat(44)}`],
    ['basic auth', 'Basic dXNlcjpwYXNz'],
    ['two spaces', `Bearer  ${'a'.repeat(43)}`],
    ['bad characters', `Bearer ${'a'.repeat(42)}+`],
    ['unknown token', `Bearer ${'a'.repeat(43)}`],
  ])('401 for a malformed or unknown bearer: %s', async (_label, value) => {
    const res = await call('/api/me', { headers: { Authorization: value } })
    expect(res.status).toBe(401)
  })

  it('a token only counts for its own kind', async () => {
    const cookieToken = await seedSession(DISCORD_ID, 'cookie')
    const desktopToken = await seedSession(DISCORD_ID, 'desktop')
    expect((await call('/api/me', { headers: bearer(cookieToken) })).status).toBe(401)
    expect((await call('/api/me', { headers: { Cookie: cookieHeader(desktopToken) } })).status).toBe(401)
  })

  it('refuses an expired bearer', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop', -1)
    expect((await call('/api/me', { headers: bearer(token) })).status).toBe(401)
  })

  it('renews a bearer close to expiry in D1 only, without a cookie', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop', 10 * 86400)
    const res = await call('/api/me', { headers: bearer(token) })
    expect(res.status).toBe(200)
    expect(res.headers.get('Set-Cookie')).toBeNull()
    const row = await sessionRow(token)
    expect(row!.expires_at).toBeGreaterThanOrEqual(nowS() + 90 * 86400 - 5)
  })

  it('records when a bearer was last used', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop')
    await env.AUTH_DB.prepare('UPDATE sessions SET last_used_at = 0').run()
    await call('/api/me', { headers: bearer(token) })
    expect((await sessionRow(token))!.last_used_at).toBeGreaterThanOrEqual(nowS() - 5)
  })

  it('still renews cookie sessions with a fresh cookie', async () => {
    const token = await seedSession(DISCORD_ID, 'cookie', 10 * 86400)
    const res = await call('/api/me', { headers: { Cookie: cookieHeader(token) } })
    expect(res.status).toBe(200)
    expect(res.headers.get('Set-Cookie')).toContain(`sl_session=${token}`)
  })
})

describe('Origin guard', () => {
  it('cookie writes still need a ScanLake Origin', async () => {
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    expect((await linkUserId({ Cookie: cookieHeader(cookie) })).status).toBe(403)
    expect((await linkUserId({ Cookie: cookieHeader(cookie), Origin: 'https://evil.example' })).status).toBe(403)
    expect((await linkUserId({ Cookie: cookieHeader(cookie), Origin: APP_ORIGIN })).status).toBe(200)
  })

  it('bearer writes need no Origin', async () => {
    const token = await seedSession(DISCORD_ID, 'desktop')
    const link = await linkUserId(bearer(token))
    expect(link.status).toBe(200)
    expect((await link.json<{ userIds: string[] }>()).userIds).toEqual([USER_ID])

    const profile = await call('/api/me/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...bearer(token) },
      body: JSON.stringify({ userName: 'Miner', org: 'Regolith' }),
    })
    expect(profile.status).toBe(200)
  })

  it('an Authorization header skips the Origin check but never falls back to the cookie', async () => {
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    const res = await linkUserId({ Authorization: 'Bearer forged', Cookie: cookieHeader(cookie) })
    expect(res.status).toBe(401)
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM user_ids').first('n')).toBe(0)
  })

  it("accepts the worker's own origin, as rewritten by wrangler dev", async () => {
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    const post = (url: string, origin: string) =>
      exports.default.fetch(
        new Request(url, {
          method: 'POST',
          redirect: 'manual',
          headers: { Cookie: cookieHeader(cookie), Origin: origin },
          body: new URLSearchParams({ decision: 'deny' }),
        }),
      )
    // Same origin over http (wrangler dev): passes the guard, then fails validation (400)
    expect((await post('http://auth.scanlake.rocks/desktop/authorize', 'http://auth.scanlake.rocks')).status).toBe(400)
    // A different scheme or host is still refused
    expect((await post('https://auth.scanlake.rocks/desktop/authorize', 'http://auth.scanlake.rocks')).status).toBe(403)
    expect((await post('http://auth.scanlake.rocks/desktop/authorize', 'http://evil.example')).status).toBe(403)
  })

  it('cookie logout still needs a ScanLake Origin', async () => {
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    expect((await call('/logout', { method: 'POST', headers: { Cookie: cookieHeader(cookie) } })).status).toBe(403)
    expect(await sessionRow(cookie)).not.toBeNull()
  })

  it('does not let browsers send Authorization cross-origin', async () => {
    const res = await call('/api/me', {
      method: 'OPTIONS',
      headers: {
        Origin: APP_ORIGIN,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'authorization',
      },
    })
    expect(res.headers.get('Access-Control-Allow-Headers')).toBe('Content-Type')
  })
})

describe('logout and account deletion', () => {
  it('bearer logout deletes only its own session', async () => {
    const desktop = await seedSession(DISCORD_ID, 'desktop')
    const cookie = await seedSession(DISCORD_ID, 'cookie')

    const res = await call('/logout', { method: 'POST', headers: bearer(desktop) })
    expect(res.status).toBe(204)
    expect(res.headers.get('Set-Cookie')).toBeNull()
    expect(await sessionRow(desktop)).toBeNull()
    expect(await sessionRow(cookie)).not.toBeNull()
    expect((await call('/api/me', { headers: bearer(desktop) })).status).toBe(401)
  })

  it('cookie logout leaves desktop sessions alone', async () => {
    const desktop = await seedSession(DISCORD_ID, 'desktop')
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    const res = await call('/logout', { method: 'POST', headers: { Cookie: cookieHeader(cookie), Origin: APP_ORIGIN } })
    expect(res.status).toBe(204)
    expect(res.headers.get('Set-Cookie')).toContain('sl_session=;')
    expect(await sessionRow(cookie)).toBeNull()
    expect(await sessionRow(desktop)).not.toBeNull()
  })

  it('DELETE /api/me removes desktop sessions and pending codes', async () => {
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    const desktop = await seedSession(DISCORD_ID, 'desktop')
    await issueCode(cookie)
    const otherDesktop = await seedSession(OTHER_ID, 'desktop')

    const res = await call('/api/me', { method: 'DELETE', headers: { Cookie: cookieHeader(cookie), Origin: APP_ORIGIN } })
    expect(res.status).toBe(204)
    expect(await sessionRow(desktop)).toBeNull()
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(0)
    expect((await call('/api/me', { headers: bearer(desktop) })).status).toBe(401)
    expect(await sessionRow(otherDesktop)).not.toBeNull()
  })

  it('DELETE /api/me works with a bearer token', async () => {
    const desktop = await seedSession(DISCORD_ID, 'desktop')
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    const res = await call('/api/me', { method: 'DELETE', headers: bearer(desktop) })
    expect(res.status).toBe(204)
    expect(await sessionRow(cookie)).toBeNull()
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM accounts WHERE discord_id = ?').bind(DISCORD_ID).first('n')).toBe(0)
  })
})

describe('deleteExpiredSessions', () => {
  it('purges expired sessions of both kinds and expired codes', async () => {
    const cookie = await seedSession(DISCORD_ID, 'cookie')
    const expiredCookie = await seedSession(DISCORD_ID, 'cookie', -1)
    const expiredDesktop = await seedSession(DISCORD_ID, 'desktop', -1)
    await issueCode(cookie)
    await issueCode(cookie)
    await env.AUTH_DB.prepare(
      'UPDATE desktop_codes SET expires_at = 0 WHERE rowid = (SELECT MIN(rowid) FROM desktop_codes)',
    ).run()

    await deleteExpiredSessions(env.AUTH_DB)

    expect(await sessionRow(cookie)).not.toBeNull()
    expect(await sessionRow(expiredCookie)).toBeNull()
    expect(await sessionRow(expiredDesktop)).toBeNull()
    expect(await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM desktop_codes').first('n')).toBe(1)
  })
})
