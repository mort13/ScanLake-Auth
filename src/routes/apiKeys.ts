import type { Context } from 'hono'
import type { AppEnv } from '../types'
import { TIERS } from '../apikeys/tiers'
import { accountTier, cleanLabel, createKey, getSettings, listKeys, revokeKey } from '../services/apiKeys'
import { readJson } from './me'

const KEY_ID_RE = /^[0-9a-f]{64}$/

/** False when the account made too many key changes in the last minute. */
async function withinRateLimit(c: Context<AppEnv>): Promise<boolean> {
  if (!c.env.API_KEY_RATE_LIMIT) return true
  const { success } = await c.env.API_KEY_RATE_LIMIT.limit({ key: `api-keys:${c.get('discordId')}` })
  return success
}

/** `GET /api/me/api-keys`: the account's tier, its limits, whether new keys can be made, and its keys. */
export async function listApiKeysRoute(c: Context<AppEnv>) {
  const discordId = c.get('discordId')
  const [tier, keys, settings] = await Promise.all([
    accountTier(c.env.AUTH_DB, discordId),
    listKeys(c.env.AUTH_DB, discordId),
    getSettings(c.env.API_KEYS),
  ])
  return c.json({ tier, limits: TIERS[tier], issuing: settings.issuing, keys })
}

/** `POST /api/me/api-keys { label }`: creates a key; the token is in this response only. */
export async function createApiKeyRoute(c: Context<AppEnv>) {
  if (!(await withinRateLimit(c))) return c.json({ error: 'Too many requests, try again in a minute' }, 429)
  const label = cleanLabel((await readJson(c)).label)

  const result = await createKey(c.env, c.get('discordId'), label)
  if (result.ok) return c.json({ token: result.token, key: result.key }, 201)

  switch (result.reason) {
    case 'paused':
      return c.json({ error: 'New API keys are paused at the moment' }, 403)
    case 'blocked':
      return c.json({ error: 'This account cannot create API keys' }, 403)
    case 'limit':
      return c.json({ error: `You already have ${result.maxKeys} active keys. Revoke one first.` }, 409)
    default:
      return c.json({ error: 'Not logged in' }, 401)
  }
}

/** `DELETE /api/me/api-keys/:id`: revokes one of the account's own keys. */
export async function revokeApiKeyRoute(c: Context<AppEnv>) {
  const id = c.req.param('id') ?? ''
  if (!KEY_ID_RE.test(id)) return c.json({ error: 'Unknown key' }, 404)
  if (!(await withinRateLimit(c))) return c.json({ error: 'Too many requests, try again in a minute' }, 429)

  const revoked = await revokeKey(c.env, id, 'user', c.get('discordId'))
  return revoked ? c.body(null, 204) : c.json({ error: 'Unknown key' }, 404)
}
