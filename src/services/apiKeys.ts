import type { Env } from '../types'
import { TIERS, gatewayLimits, isTier, type Tier } from '../apikeys/tiers'
import { nowS, sha256Hex } from './session'

/**
 * User API keys for ScanLake Gateway.
 *
 * The token is `slk_` + 64 hex chars, shown once. D1 (`api_keys`) is the source of
 * truth; each active key also has a KV entry `ukey:<sha256>` that the Gateway reads on
 * every request. ScanLake Store reads the same namespace but only `apikey:*` with
 * `sk_` tokens, so these keys can never upload or read raw data there.
 */

export const TOKEN_RE = /^slk_[0-9a-f]{64}$/
/** Characters of the token kept for display: "slk_" + 8 hex. */
const PREFIX_LENGTH = 12
const MAX_LABEL_LENGTH = 64
/** Most keys (active and revoked) returned for one account. */
const MAX_LISTED = 50

export const SETTINGS_KEY = 'config:user-keys'

export interface UserKeySettings {
  /** New keys can be created. */
  issuing: boolean
  /** The Gateway accepts user keys. */
  serving: boolean
}

/** What the Gateway reads from `ukey:<hash>` (its `ApiKeyMeta` with `kind: "user"`). */
export interface GatewayKeyMeta {
  kind: 'user'
  ownerId: string
  discordId: string
  tier: Tier
  active: true
  limits: { limit: number; windowMs: number }[]
  rateLimit: number
  rateLimitWindowMs: number
  maxUploadBytes: 0
  allowedOrigins: string[]
  scopes: string[]
  createdAt: string
}

export interface ApiKeyRow {
  key_hash: string
  discord_id: string
  user_id: string | null
  label: string
  prefix: string
  created_at: number
  revoked_at: number | null
  revoked_by: string | null
}

/** A key as the account owner sees it. */
export interface ApiKeyInfo {
  id: string
  prefix: string
  label: string
  createdAt: number
  revokedAt: number | null
  revokedBy: string | null
}

export function kvKey(keyHash: string): string {
  return `ukey:${keyHash}`
}

export function toInfo(row: ApiKeyRow): ApiKeyInfo {
  return {
    id: row.key_hash,
    prefix: row.prefix,
    label: row.label,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
    revokedBy: row.revoked_by,
  }
}

export function cleanLabel(value: unknown): string {
  return typeof value === 'string' ? value.trim().slice(0, MAX_LABEL_LENGTH) : ''
}

function generateToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return `slk_${[...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')}`
}

export async function getSettings(kv: KVNamespace): Promise<UserKeySettings> {
  const stored = await kv.get<Partial<UserKeySettings>>(SETTINGS_KEY, 'json')
  return { issuing: stored?.issuing !== false, serving: stored?.serving !== false }
}

export async function putSettings(kv: KVNamespace, settings: UserKeySettings): Promise<void> {
  await kv.put(SETTINGS_KEY, JSON.stringify(settings))
}

export function gatewayMeta(
  discordId: string,
  primaryUserId: string | null,
  tier: Tier,
  createdAtS: number,
): GatewayKeyMeta {
  const limits = gatewayLimits(tier)
  const daily = limits[limits.length - 1]
  return {
    kind: 'user',
    // The Gateway logs this as the key's userId
    ownerId: primaryUserId ?? `discord:${discordId}`,
    discordId,
    tier,
    active: true,
    limits,
    // Older Gateway code reads only these two
    rateLimit: daily.limit,
    rateLimitWindowMs: daily.windowMs,
    maxUploadBytes: 0,
    allowedOrigins: [],
    scopes: ['derived:public'],
    createdAt: new Date(createdAtS * 1000).toISOString(),
  }
}

interface AccountApiRow {
  api_tier: string
  primary_user_id: string | null
}

async function loadAccount(db: D1Database, discordId: string): Promise<{ tier: Tier; primaryUserId: string | null } | null> {
  const row = await db
    .prepare('SELECT api_tier, primary_user_id FROM accounts WHERE discord_id = ?')
    .bind(discordId)
    .first<AccountApiRow>()
  if (!row) return null
  return { tier: isTier(row.api_tier) ? row.api_tier : 'verified', primaryUserId: row.primary_user_id }
}

export async function accountTier(db: D1Database, discordId: string): Promise<Tier> {
  return (await loadAccount(db, discordId))?.tier ?? 'verified'
}

export async function listKeys(db: D1Database, discordId: string): Promise<ApiKeyInfo[]> {
  const { results } = await db
    .prepare(
      `SELECT * FROM api_keys WHERE discord_id = ?
       ORDER BY revoked_at IS NOT NULL, created_at DESC, rowid DESC LIMIT ${MAX_LISTED}`,
    )
    .bind(discordId)
    .all<ApiKeyRow>()
  return results.map(toInfo)
}

export type CreateResult =
  | { ok: true; token: string; key: ApiKeyInfo }
  | { ok: false; reason: 'paused' | 'blocked' | 'limit' | 'no-account'; maxKeys?: number }

/**
 * Creates a key for the account, unless issuing is paused, the account is blocked or
 * already holds its tier's maximum of active keys. The count check and the insert are
 * one statement, so two parallel requests can't both get past the limit.
 */
export async function createKey(env: Env, discordId: string, label: string): Promise<CreateResult> {
  const [account, settings] = await Promise.all([loadAccount(env.AUTH_DB, discordId), getSettings(env.API_KEYS)])
  if (!account) return { ok: false, reason: 'no-account' }
  if (!settings.issuing) return { ok: false, reason: 'paused' }
  const { maxKeys } = TIERS[account.tier]
  if (account.tier === 'blocked' || maxKeys <= 0) return { ok: false, reason: 'blocked' }

  const token = generateToken()
  const keyHash = await sha256Hex(token)
  const now = nowS()
  const row: ApiKeyRow = {
    key_hash: keyHash,
    discord_id: discordId,
    user_id: account.primaryUserId,
    label,
    prefix: token.slice(0, PREFIX_LENGTH),
    created_at: now,
    revoked_at: null,
    revoked_by: null,
  }

  const insert = await env.AUTH_DB.prepare(
    `INSERT INTO api_keys (key_hash, discord_id, user_id, label, prefix, created_at)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6
     WHERE (SELECT COUNT(*) FROM api_keys WHERE discord_id = ?2 AND revoked_at IS NULL) < ?7`,
  )
    .bind(row.key_hash, row.discord_id, row.user_id, row.label, row.prefix, row.created_at, maxKeys)
    .run()
  if (!insert.meta.changes) return { ok: false, reason: 'limit', maxKeys }

  try {
    const meta = gatewayMeta(discordId, account.primaryUserId, account.tier, now)
    await env.API_KEYS.put(kvKey(keyHash), JSON.stringify(meta))
  } catch (err) {
    // Without its KV entry the key would never work: don't leave a dead row behind
    await env.AUTH_DB.prepare('DELETE FROM api_keys WHERE key_hash = ?').bind(keyHash).run()
    throw err
  }
  return { ok: true, token, key: toInfo(row) }
}

/**
 * Revokes one key: marks the row and deletes the KV entry (the Gateway stops accepting
 * it within about a minute). With `discordId`, only that account's key is touched.
 * Returns false when there is no such active key.
 */
export async function revokeKey(
  env: Env,
  keyHash: string,
  revokedBy: 'user' | 'admin',
  discordId?: string,
): Promise<boolean> {
  const sql = `UPDATE api_keys SET revoked_at = ?, revoked_by = ?
               WHERE key_hash = ? AND revoked_at IS NULL${discordId === undefined ? '' : ' AND discord_id = ?'}`
  const params: (string | number)[] = [nowS(), revokedBy, keyHash]
  if (discordId !== undefined) params.push(discordId)
  const result = await env.AUTH_DB.prepare(sql).bind(...params).run()
  if (!result.meta.changes) return false
  await env.API_KEYS.delete(kvKey(keyHash))
  return true
}

async function activeKeyHashes(db: D1Database, discordId: string): Promise<string[]> {
  const { results } = await db
    .prepare('SELECT key_hash FROM api_keys WHERE discord_id = ? AND revoked_at IS NULL')
    .bind(discordId)
    .all<{ key_hash: string }>()
  return results.map((r) => r.key_hash)
}

/** Revokes every active key of the account; returns how many. */
export async function revokeAllForAccount(env: Env, discordId: string, revokedBy: 'admin' | 'blocked'): Promise<number> {
  const hashes = await activeKeyHashes(env.AUTH_DB, discordId)
  if (hashes.length === 0) return 0
  await env.AUTH_DB.prepare(
    'UPDATE api_keys SET revoked_at = ?, revoked_by = ? WHERE discord_id = ? AND revoked_at IS NULL',
  )
    .bind(nowS(), revokedBy, discordId)
    .run()
  await Promise.all(hashes.map((hash) => env.API_KEYS.delete(kvKey(hash))))
  return hashes.length
}

/**
 * Sets the account's tier. Blocking revokes all its keys; any other tier rewrites the
 * KV entries of its active keys, so the new limits apply within about a minute.
 * Returns false when the account doesn't exist.
 */
export async function setTier(env: Env, discordId: string, tier: Tier): Promise<boolean> {
  const result = await env.AUTH_DB.prepare('UPDATE accounts SET api_tier = ?, updated_at = ? WHERE discord_id = ?')
    .bind(tier, nowS(), discordId)
    .run()
  if (!result.meta.changes) return false

  if (tier === 'blocked') {
    await revokeAllForAccount(env, discordId, 'blocked')
    return true
  }
  const { results } = await env.AUTH_DB.prepare(
    `SELECT k.key_hash, k.created_at, a.primary_user_id
     FROM api_keys k JOIN accounts a ON a.discord_id = k.discord_id
     WHERE k.discord_id = ? AND k.revoked_at IS NULL`,
  )
    .bind(discordId)
    .all<{ key_hash: string; created_at: number; primary_user_id: string | null }>()
  await Promise.all(
    results.map((r) =>
      env.API_KEYS.put(kvKey(r.key_hash), JSON.stringify(gatewayMeta(discordId, r.primary_user_id, tier, r.created_at))),
    ),
  )
  return true
}

/** Removes the KV entries of all the account's keys; the rows go with the account. */
export async function deleteAccountKeys(env: Env, discordId: string): Promise<void> {
  const hashes = await activeKeyHashes(env.AUTH_DB, discordId)
  await Promise.all(hashes.map((hash) => env.API_KEYS.delete(kvKey(hash))))
}
