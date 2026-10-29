import type { MiddlewareHandler } from 'hono'
import type { AppEnv } from '../types'
import { readSession } from '../services/session'

/** 401 unless the request carries a valid session cookie or bearer token; sets `discordId` and `sessionKind`. */
export const requireSession: MiddlewareHandler<AppEnv> = async (c, next) => {
  const session = await readSession(c)
  if (!session) return c.json({ error: 'Not logged in' }, 401)
  c.set('discordId', session.discordId)
  c.set('sessionKind', session.kind)
  return next()
}
