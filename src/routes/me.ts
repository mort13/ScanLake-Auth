import type { Context } from 'hono'
import type { AppEnv } from '../types'
import { clearSessionCookie } from '../services/session'
import { MAX_USER_IDS, deleteAccount, linkUserId, loadMe, saveProfile } from '../services/accounts'

// Same format the Store accepts for uploads
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_FIELD_LENGTH = 64

async function meResponse(c: Context<AppEnv>) {
  const me = await loadMe(c.env.AUTH_DB, c.get('discordId'))
  return me ? c.json(me) : c.json({ error: 'Not logged in' }, 401)
}

async function readJson(c: Context<AppEnv>): Promise<Record<string, unknown>> {
  try {
    const body = await c.req.json<unknown>()
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

/** `GET /api/me` */
export async function getMeRoute(c: Context<AppEnv>) {
  return meResponse(c)
}

/** `POST /api/me/user-ids { userId }`: links a ScanLake userId to the account. */
export async function linkUserIdRoute(c: Context<AppEnv>) {
  const body = await readJson(c)
  const userId = typeof body.userId === 'string' ? body.userId.toLowerCase() : ''
  if (!UUID_RE.test(userId)) {
    return c.json({ error: 'Invalid or missing userId (must be UUID v4)' }, 400)
  }

  const result = await linkUserId(c.env.AUTH_DB, c.get('discordId'), userId)
  if (result === 'taken') {
    return c.json({ error: 'This ID is already linked to another Discord account' }, 409)
  }
  if (result === 'limit') {
    return c.json({ error: `An account can hold at most ${MAX_USER_IDS} IDs` }, 422)
  }
  return meResponse(c)
}

/** `PUT /api/me/profile { userName, org }`: stores the Capture profile. */
export async function saveProfileRoute(c: Context<AppEnv>) {
  const body = await readJson(c)
  if (typeof body.userName !== 'string' || typeof body.org !== 'string') {
    return c.json({ error: 'userName and org must be strings' }, 400)
  }
  const userName = body.userName.trim().slice(0, MAX_FIELD_LENGTH)
  const org = body.org.trim().slice(0, MAX_FIELD_LENGTH)

  await saveProfile(c.env.AUTH_DB, c.get('discordId'), userName, org)
  return meResponse(c)
}

/** `DELETE /api/me`: unlinks Discord by deleting everything stored about the account. */
export async function deleteMeRoute(c: Context<AppEnv>) {
  await deleteAccount(c.env.AUTH_DB, c.get('discordId'))
  clearSessionCookie(c)
  return c.body(null, 204)
}
