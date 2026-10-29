import type { MiddlewareHandler } from 'hono'
import type { AppEnv } from '../types'
import { readSession } from '../services/session'

/** 401 unless the request carries a valid session cookie; sets `discordId`. */
export const requireSession: MiddlewareHandler<AppEnv> = async (c, next) => {
  const discordId = await readSession(c)
  if (!discordId) return c.json({ error: 'Not logged in' }, 401)
  c.set('discordId', discordId)
  return next()
}
