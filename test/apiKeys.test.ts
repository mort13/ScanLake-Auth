import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/services/session'
import { SETTINGS_KEY, kvKey, type GatewayKeyMeta } from '../src/services/apiKeys'
import { APP_ORIGIN, DISCORD_ID, bearer, call, cookieHeader, resetDb, seedAccount, seedSession } from './helpers'

const OTHER_ID = '100000000000000002'
const ADMIN_ID = '100000000000000009'
const USER_ID = '0b5e3f9a-3c1d-4e2f-9a8b-7c6d5e4f3a2b'
const TOKEN_RE = /^slk_[0-9a-f]{64}$/

interface KeyInfo {
  id: string
  prefix: string
  label: string
  createdAt: number
  revokedAt: number | null
  revokedBy: string | null
}

let cookie: string

beforeEach(async () => {
  await resetDb()
  await seedAccount()
  await seedAccount(OTHER_ID, { username: 'other', globalName: 'Other' })
  cookie = await seedSession()
})

function headers(token = cookie): Record<string, string> {
  return { Cookie: cookieHeader(token), Origin: APP_ORIGIN, 'Content-Type': 'application/json' }
}

function create(label = 'my tool', token = cookie) {
  return call('/api/me/api-keys', { method: 'POST', headers: headers(token), body: JSON.stringify({ label }) })
}

async function createOk(label?: string, token?: string): Promise<{ token: string; key: KeyInfo }> {
  const res = await create(label, token)
  expect(res.status).toBe(201)
  return res.json()
}

function revoke(id: string, token = cookie) {
  return call(`/api/me/api-keys/${id}`, { method: 'DELETE', headers: headers(token) })
}

async function list(token = cookie) {
  const res = await call('/api/me/api-keys', { headers: headers(token) })
  expect(res.status).toBe(200)
  return res.json<{ tier: string; limits: { maxKeys: number }; issuing: boolean; keys: KeyInfo[] }>()
}

async function kvMeta(token: string): Promise<GatewayKeyMeta | null> {
  return env.API_KEYS.get<GatewayKeyMeta>(kvKey(await sha256Hex(token)), 'json')
}

describe('GET /api/me', () => {
  it('reports the API tier and that a normal account is no admin', async () => {
    const me = await (await call('/api/me', { headers: headers() })).json<{ apiTier: string; isAdmin: boolean }>()
    expect(me.apiTier).toBe('verified')
    expect(me.isAdmin).toBe(false)
  })

  it('flags the accounts in ADMIN_DISCORD_IDS', async () => {
    await seedAccount(ADMIN_ID, { username: 'boss' })
    const token = await seedSession(ADMIN_ID)
    const me = await (await call('/api/me', { headers: headers(token) })).json<{ isAdmin: boolean }>()
    expect(me.isAdmin).toBe(true)
  })
})

describe('creating keys', () => {
  it('needs a session', async () => {
    expect((await call('/api/me/api-keys')).status).toBe(401)
    const res = await call('/api/me/api-keys', {
      method: 'POST',
      headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(res.status).toBe(401)
  })

  it('refuses cookie writes from a foreign origin', async () => {
    const res = await call('/api/me/api-keys', {
      method: 'POST',
      headers: { ...headers(), Origin: 'https://evil.example' },
      body: '{}',
    })
    expect(res.status).toBe(403)
    expect(await list()).toMatchObject({ keys: [] })
  })

  it('returns the token once and writes the Gateway KV entry', async () => {
    const { token, key } = await createOk('  my tool  ')
    expect(token).toMatch(TOKEN_RE)
    expect(key.prefix).toBe(token.slice(0, 12))
    expect(key.label).toBe('my tool')
    expect(key.id).toBe(await sha256Hex(token))

    const meta = await kvMeta(token)
    expect(meta).toMatchObject({
      kind: 'user',
      ownerId: `discord:${DISCORD_ID}`,
      discordId: DISCORD_ID,
      tier: 'verified',
      active: true,
      limits: [
        { limit: 60, windowMs: 60_000 },
        { limit: 2000, windowMs: 86_400_000 },
      ],
      rateLimit: 2000,
      rateLimitWindowMs: 86_400_000,
      maxUploadBytes: 0,
      allowedOrigins: [],
      scopes: ['derived:public'],
    })
    // Never under the prefix ScanLake Store reads
    expect(await env.API_KEYS.get(`apikey:${key.id}`)).toBeNull()

    const listed = await list()
    expect(listed.tier).toBe('verified')
    expect(listed.keys).toEqual([key])
    expect(JSON.stringify(listed)).not.toContain(token)
  })

  it('uses the primary ScanLake user ID as owner', async () => {
    const link = await call('/api/me/user-ids', {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ userId: USER_ID }),
    })
    expect(link.status).toBe(200)
    const { token, key } = await createOk()
    expect((await kvMeta(token))?.ownerId).toBe(USER_ID)
    const row = await env.AUTH_DB.prepare('SELECT user_id FROM api_keys WHERE key_hash = ?').bind(key.id).first()
    expect(row).toEqual({ user_id: USER_ID })
  })

  it('cuts long labels and accepts a missing one', async () => {
    expect((await createOk('x'.repeat(100))).key.label).toHaveLength(64)
    const res = await call('/api/me/api-keys', { method: 'POST', headers: headers(), body: 'not json' })
    expect(res.status).toBe(201)
    expect((await res.json<{ key: KeyInfo }>()).key.label).toBe('')
  })

  it('works with a desktop bearer token', async () => {
    const desktop = await seedSession(DISCORD_ID, 'desktop')
    const res = await call('/api/me/api-keys', {
      method: 'POST',
      headers: { ...bearer(desktop), 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(res.status).toBe(201)
  })

  it('allows the tier maximum of active keys', async () => {
    const first = await createOk('a')
    await createOk('b')
    const res = await create('c')
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'You already have 2 active keys. Revoke one first.' })

    expect((await revoke(first.key.id)).status).toBe(204)
    await createOk('c')
    expect((await list()).keys.map((k) => k.label)).toEqual(['c', 'b', 'a'])
  })

  it('refuses new keys while issuing is paused', async () => {
    await env.API_KEYS.put(SETTINGS_KEY, JSON.stringify({ issuing: false, serving: true }))
    const res = await create()
    expect(res.status).toBe(403)
    expect((await list()).issuing).toBe(false)
  })

  it('refuses blocked accounts', async () => {
    await env.AUTH_DB.prepare("UPDATE accounts SET api_tier = 'blocked' WHERE discord_id = ?").bind(DISCORD_ID).run()
    expect((await create()).status).toBe(403)
    expect(await list()).toMatchObject({ tier: 'blocked', limits: { maxKeys: 0 } })
  })
})

describe('revoking keys', () => {
  it('deletes the KV entry and keeps the row as revoked', async () => {
    const { token, key } = await createOk()
    expect((await revoke(key.id)).status).toBe(204)
    expect(await kvMeta(token)).toBeNull()

    const [listed] = (await list()).keys
    expect(listed.id).toBe(key.id)
    expect(listed.revokedBy).toBe('user')
    expect(listed.revokedAt).toEqual(expect.any(Number))

    expect((await revoke(key.id)).status).toBe(404)
  })

  it("can't touch another account's key", async () => {
    const other = await seedSession(OTHER_ID)
    const { token, key } = await createOk('theirs', other)
    expect((await revoke(key.id)).status).toBe(404)
    expect(await kvMeta(token)).not.toBeNull()
  })

  it('404s malformed ids', async () => {
    expect((await revoke('nope')).status).toBe(404)
  })

  it('DELETE /api/me removes the keys and their KV entries', async () => {
    const { token } = await createOk()
    expect((await call('/api/me', { method: 'DELETE', headers: headers() })).status).toBe(204)
    expect(await kvMeta(token)).toBeNull()
    const { n } = (await env.AUTH_DB.prepare('SELECT COUNT(*) AS n FROM api_keys').first<{ n: number }>())!
    expect(n).toBe(0)
  })
})
