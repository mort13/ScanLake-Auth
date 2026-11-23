import type { Context } from 'hono'
import type { AppEnv } from '../types'
import { TIERS, isTier } from '../apikeys/tiers'
import { getSettings, putSettings, revokeKey, setTier, type ApiKeyRow } from '../services/apiKeys'
import { loadUsage, type KeyUsage } from '../services/usage'
import { readJson } from './me'

const KEY_ID_RE = /^[0-9a-f]{64}$/
const DISCORD_ID_RE = /^\d{5,25}$/
const DEFAULT_DATASET = 'scanlake_gateway_usage'

interface AdminKeyRow extends ApiKeyRow {
  username: string
  global_name: string | null
  api_tier: string
  primary_user_id: string | null
}

/**
 * `GET /api/admin/api-keys`: every user key with its account (Discord ID and names,
 * ScanLake user ID, tier) and usage, keys that aren't user keys (Dashboard, Refinery)
 * by their owner, summary counts, the on/off switches and the tier table.
 */
export async function adminListRoute(c: Context<AppEnv>) {
  const [{ results }, settings, usage] = await Promise.all([
    c.env.AUTH_DB.prepare(
      `SELECT k.*, a.username, a.global_name, a.api_tier, a.primary_user_id
       FROM api_keys k JOIN accounts a ON a.discord_id = k.discord_id
       ORDER BY k.revoked_at IS NOT NULL, k.created_at DESC, k.rowid DESC`,
    ).all<AdminKeyRow>(),
    getSettings(c.env.API_KEYS),
    loadUsage(c.env.ANALYTICS_SQL, c.env.USAGE_DATASET || DEFAULT_DATASET),
  ])

  const usageOf = (hash: string): KeyUsage | null => usage.keys[hash]?.usage ?? null
  const keys = results.map((row) => ({
    id: row.key_hash,
    prefix: row.prefix,
    label: row.label,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
    revokedBy: row.revoked_by,
    status: row.revoked_at === null ? 'active' : 'revoked',
    discordId: row.discord_id,
    username: row.username,
    globalName: row.global_name,
    // The ScanLake user ID when the key was made, else the account's current primary
    userId: row.user_id ?? row.primary_user_id,
    tier: isTier(row.api_tier) ? row.api_tier : 'verified',
    usage: usageOf(row.key_hash),
  }))

  const userKeyHashes = new Set(results.map((r) => r.key_hash))
  const internal = Object.entries(usage.keys)
    .filter(([hash, entry]) => !userKeyHashes.has(hash) && entry.kind !== 'user')
    .map(([hash, entry]) => ({ id: hash, prefix: hash.slice(0, 8), ownerId: entry.ownerId, usage: entry.usage }))
    .sort((a, b) => b.usage.requests30d - a.usage.requests30d)

  const active = keys.filter((k) => k.status === 'active')
  const userUsage = keys.map((k) => k.usage).filter((u): u is KeyUsage => u !== null)
  const sum = (pick: (u: KeyUsage) => number) => userUsage.reduce((total, u) => total + pick(u), 0)

  return c.json({
    settings,
    tiers: TIERS,
    usageAvailable: usage.available,
    usageError: usage.error ?? null,
    days: usage.days,
    summary: {
      totalKeys: keys.length,
      activeKeys: active.length,
      accountsWithKeys: new Set(active.map((k) => k.discordId)).size,
      requests24h: sum((u) => u.requests24h),
      requests30d: sum((u) => u.requests30d),
    },
    keys,
    internal,
  })
}

/** `POST /api/admin/api-keys/:id/revoke` */
export async function adminRevokeRoute(c: Context<AppEnv>) {
  const id = c.req.param('id') ?? ''
  if (!KEY_ID_RE.test(id)) return c.json({ error: 'Unknown key' }, 404)
  return (await revokeKey(c.env, id, 'admin')) ? c.body(null, 204) : c.json({ error: 'Unknown or already revoked key' }, 404)
}

/** `PUT /api/admin/accounts/:discordId/tier { tier }` */
export async function adminSetTierRoute(c: Context<AppEnv>) {
  const discordId = c.req.param('discordId') ?? ''
  const { tier } = await readJson(c)
  if (!DISCORD_ID_RE.test(discordId)) return c.json({ error: 'Unknown account' }, 404)
  if (!isTier(tier)) return c.json({ error: `tier must be one of ${Object.keys(TIERS).join(', ')}` }, 400)
  if (!(await setTier(c.env, discordId, tier))) return c.json({ error: 'Unknown account' }, 404)
  return c.json({ discordId, tier })
}

/** `GET /api/admin/settings` */
export async function adminGetSettingsRoute(c: Context<AppEnv>) {
  return c.json(await getSettings(c.env.API_KEYS))
}

/** `PUT /api/admin/settings { issuing?, serving? }`: fields left out keep their value. */
export async function adminPutSettingsRoute(c: Context<AppEnv>) {
  const body = await readJson(c)
  for (const field of ['issuing', 'serving'] as const) {
    if (body[field] !== undefined && typeof body[field] !== 'boolean') {
      return c.json({ error: `${field} must be true or false` }, 400)
    }
  }
  const current = await getSettings(c.env.API_KEYS)
  const next = {
    issuing: typeof body.issuing === 'boolean' ? body.issuing : current.issuing,
    serving: typeof body.serving === 'boolean' ? body.serving : current.serving,
  }
  await putSettings(c.env.API_KEYS, next)
  return c.json(next)
}
