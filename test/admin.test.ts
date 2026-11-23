import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/services/session'
import { SETTINGS_KEY, kvKey, type GatewayKeyMeta } from '../src/services/apiKeys'
import { buildReport, clearUsageCache, loadUsage, parseTimestamp } from '../src/services/usage'
import { APP_ORIGIN, DISCORD_ID, call, cookieHeader, resetDb, seedAccount, seedSession } from './helpers'

const ADMIN_ID = '100000000000000009'

let userCookie: string
let adminCookie: string

beforeEach(async () => {
  await resetDb()
  clearUsageCache()
  await seedAccount(DISCORD_ID, { username: 'miner', globalName: 'Rock Miner' })
  await seedAccount(ADMIN_ID, { username: 'boss', globalName: null })
  userCookie = await seedSession(DISCORD_ID)
  adminCookie = await seedSession(ADMIN_ID)
})

function headers(token: string): Record<string, string> {
  return { Cookie: cookieHeader(token), Origin: APP_ORIGIN, 'Content-Type': 'application/json' }
}

async function createKey(label = 'tool'): Promise<{ token: string; id: string }> {
  const res = await call('/api/me/api-keys', {
    method: 'POST',
    headers: headers(userCookie),
    body: JSON.stringify({ label }),
  })
  expect(res.status).toBe(201)
  const body = await res.json<{ token: string; key: { id: string } }>()
  return { token: body.token, id: body.key.id }
}

function admin(path: string, init: { method?: string; body?: unknown } = {}, token = adminCookie) {
  return call(path, {
    method: init.method ?? 'GET',
    headers: headers(token),
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  })
}

async function kvMeta(token: string): Promise<GatewayKeyMeta | null> {
  return env.API_KEYS.get<GatewayKeyMeta>(kvKey(await sha256Hex(token)), 'json')
}

interface AdminList {
  settings: { issuing: boolean; serving: boolean }
  usageAvailable: boolean
  summary: { totalKeys: number; activeKeys: number; accountsWithKeys: number }
  keys: {
    id: string
    label: string
    status: string
    revokedBy: string | null
    discordId: string
    username: string
    globalName: string | null
    userId: string | null
    tier: string
    usage: unknown
  }[]
  internal: unknown[]
}

describe('access', () => {
  it('is admins only', async () => {
    expect((await call('/api/admin/api-keys')).status).toBe(401)
    expect((await admin('/api/admin/api-keys', {}, userCookie)).status).toBe(403)
    expect((await admin('/api/admin/settings', { method: 'PUT', body: { serving: false } }, userCookie)).status).toBe(403)
    expect((await admin('/api/admin/api-keys')).status).toBe(200)
  })
})

describe('GET /api/admin/api-keys', () => {
  it('lists keys with their Discord account and ScanLake user ID', async () => {
    const userId = '0b5e3f9a-3c1d-4e2f-9a8b-7c6d5e4f3a2b'
    await env.AUTH_DB.prepare('UPDATE accounts SET primary_user_id = ? WHERE discord_id = ?').bind(userId, DISCORD_ID).run()
    const a = await createKey('a')
    const b = await createKey('b')
    await call(`/api/me/api-keys/${a.id}`, { method: 'DELETE', headers: headers(userCookie) })

    const res = await admin('/api/admin/api-keys')
    const body = await res.json<AdminList>()
    expect(body.settings).toEqual({ issuing: true, serving: true })
    // No Analytics SQL binding in tests: the list still works, without usage
    expect(body.usageAvailable).toBe(false)
    expect(body.summary).toMatchObject({ totalKeys: 2, activeKeys: 1, accountsWithKeys: 1 })
    expect(body.keys.map((k) => [k.id, k.status, k.revokedBy])).toEqual([
      [b.id, 'active', null],
      [a.id, 'revoked', 'user'],
    ])
    expect(body.keys[0]).toMatchObject({
      label: 'b',
      discordId: DISCORD_ID,
      username: 'miner',
      globalName: 'Rock Miner',
      userId,
      tier: 'verified',
      usage: null,
    })
    expect(JSON.stringify(body)).not.toContain(b.token)
  })
})

describe('revoking and tiers', () => {
  it('revokes any key', async () => {
    const { token, id } = await createKey()
    expect((await admin(`/api/admin/api-keys/${id}/revoke`, { method: 'POST' })).status).toBe(204)
    expect(await kvMeta(token)).toBeNull()
    expect((await admin(`/api/admin/api-keys/${id}/revoke`, { method: 'POST' })).status).toBe(404)
    const body = await (await admin('/api/admin/api-keys')).json<AdminList>()
    expect(body.keys[0]).toMatchObject({ status: 'revoked', revokedBy: 'admin' })
  })

  it('trusted rewrites the limits of active keys', async () => {
    const { token } = await createKey()
    const res = await admin(`/api/admin/accounts/${DISCORD_ID}/tier`, { method: 'PUT', body: { tier: 'trusted' } })
    expect(res.status).toBe(200)
    expect(await kvMeta(token)).toMatchObject({
      tier: 'trusted',
      limits: [
        { limit: 600, windowMs: 60_000 },
        { limit: 20_000, windowMs: 86_400_000 },
      ],
      rateLimit: 20_000,
    })
    // Trusted accounts may hold up to five keys
    for (let i = 0; i < 4; i++) await createKey(`k${i}`)
    const sixth = await call('/api/me/api-keys', { method: 'POST', headers: headers(userCookie), body: '{}' })
    expect(sixth.status).toBe(409)
  })

  it('blocked revokes every key and stops new ones', async () => {
    const one = await createKey('one')
    const two = await createKey('two')
    expect((await admin(`/api/admin/accounts/${DISCORD_ID}/tier`, { method: 'PUT', body: { tier: 'blocked' } })).status).toBe(200)
    expect(await kvMeta(one.token)).toBeNull()
    expect(await kvMeta(two.token)).toBeNull()

    const body = await (await admin('/api/admin/api-keys')).json<AdminList>()
    expect(body.keys.map((k) => k.revokedBy)).toEqual(['blocked', 'blocked'])
    expect(body.keys.every((k) => k.tier === 'blocked')).toBe(true)
    const again = await call('/api/me/api-keys', { method: 'POST', headers: headers(userCookie), body: '{}' })
    expect(again.status).toBe(403)

    // Unblocking allows new keys; the revoked ones stay revoked
    await admin(`/api/admin/accounts/${DISCORD_ID}/tier`, { method: 'PUT', body: { tier: 'verified' } })
    expect(await kvMeta(one.token)).toBeNull()
    await createKey('three')
  })

  it('validates tier and account', async () => {
    expect((await admin(`/api/admin/accounts/${DISCORD_ID}/tier`, { method: 'PUT', body: { tier: 'gold' } })).status).toBe(400)
    expect((await admin('/api/admin/accounts/123456789012345678/tier', { method: 'PUT', body: { tier: 'trusted' } })).status).toBe(404)
    expect((await admin('/api/admin/accounts/abc/tier', { method: 'PUT', body: { tier: 'trusted' } })).status).toBe(404)
  })
})

describe('settings', () => {
  it('defaults to on and stores partial updates', async () => {
    expect(await (await admin('/api/admin/settings')).json()).toEqual({ issuing: true, serving: true })
    const res = await admin('/api/admin/settings', { method: 'PUT', body: { serving: false } })
    expect(await res.json()).toEqual({ issuing: true, serving: false })
    expect(await env.API_KEYS.get(SETTINGS_KEY, 'json')).toEqual({ issuing: true, serving: false })

    await admin('/api/admin/settings', { method: 'PUT', body: { issuing: false } })
    expect(await (await admin('/api/admin/settings')).json()).toEqual({ issuing: false, serving: false })
  })

  it('rejects non-boolean values', async () => {
    expect((await admin('/api/admin/settings', { method: 'PUT', body: { serving: 'no' } })).status).toBe(400)
  })
})

describe('usage report', () => {
  const NOW = Date.parse('2026-11-23T12:30:00Z')
  const KEY = 'a'.repeat(64)
  const INTERNAL = 'b'.repeat(64)

  const rows = [
    // 2 h ago
    { key_hash: KEY, kind: 'user', owner_id: 'u1', discord_id: DISCORD_ID, hour: '2026-11-23 10:00:00', requests: '5', bytes: '5000', limited: '1' },
    // 3 days ago
    { key_hash: KEY, kind: 'user', owner_id: 'u1', discord_id: DISCORD_ID, hour: '2026-11-20 08:00:00', requests: 7, bytes: 700, limited: 0 },
    // 20 days ago
    { key_hash: KEY, kind: 'user', owner_id: 'u1', discord_id: DISCORD_ID, hour: '2026-11-03 23:00:00', requests: 11, bytes: 0, limited: 0 },
    { key_hash: INTERNAL, kind: 'internal', owner_id: 'dashboard', discord_id: '', hour: '2026-11-23T11:00:00Z', requests: 100, bytes: 1, limited: 0 },
  ]

  it('adds hourly rows up into windows and a daily series', () => {
    const report = buildReport(rows, NOW)
    expect(report.days).toHaveLength(30)
    expect(report.days[29]).toBe('2026-11-23')
    const usage = report.keys[KEY].usage
    expect(usage).toMatchObject({
      requests24h: 5,
      requests7d: 12,
      requests30d: 23,
      bytes30d: 5700,
      limited30d: 1,
      lastUsedAt: Date.parse('2026-11-23T10:00:00Z') / 1000,
    })
    expect(usage.daily[29]).toBe(5)
    expect(usage.daily[26]).toBe(7)
    expect(usage.daily[report.days.indexOf('2026-11-03')]).toBe(11)
    expect(report.keys[INTERNAL]).toMatchObject({ kind: 'internal', ownerId: 'dashboard' })
  })

  it('parses the timestamp formats the SQL API may return', () => {
    expect(parseTimestamp('2026-11-23 10:00:00')).toBe(Date.parse('2026-11-23T10:00:00Z'))
    expect(parseTimestamp('2026-11-23T10:00:00Z')).toBe(Date.parse('2026-11-23T10:00:00Z'))
    expect(parseTimestamp(1_795_000_000)).toBe(1_795_000_000_000)
    expect(parseTimestamp('garbage')).toBeNull()
  })

  it('queries the dataset through the binding and caches the result', async () => {
    const queries: { query: string; params?: unknown }[] = []
    const binding = {
      async query(request: { query: string; params?: unknown }) {
        queries.push(request)
        return { data: rows, rows: rows.length, statistics: { elapsed_ms: 1, rows_read: 4, bytes_read: 1 } }
      },
    } as unknown as AnalyticsSQLBinding

    const report = await loadUsage(binding, 'scanlake_gateway_usage', NOW)
    expect(report.available).toBe(true)
    expect(report.keys[KEY].usage.requests30d).toBe(23)
    expect(queries[0].query).toContain('FROM events.analyticsEngine.scanlake_gateway_usage')
    expect(queries[0].params).toEqual({ start: '2026-10-25T00:00:00.000Z' })

    await loadUsage(binding, 'scanlake_gateway_usage', NOW + 30_000)
    expect(queries).toHaveLength(1)
  })

  it('reports failures instead of throwing', async () => {
    const failing = {
      async query() {
        throw new Error('no entitlement')
      },
    } as unknown as AnalyticsSQLBinding
    expect(await loadUsage(failing, 'scanlake_gateway_usage', NOW)).toMatchObject({ available: false, error: 'no entitlement' })
    expect(await loadUsage(undefined, 'scanlake_gateway_usage', NOW)).toMatchObject({ available: false })
    expect(await loadUsage(failing, 'bad name; DROP', NOW)).toMatchObject({ available: false, error: 'Invalid USAGE_DATASET' })
  })
})
