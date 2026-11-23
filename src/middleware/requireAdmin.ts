import type { MiddlewareHandler } from 'hono'
import type { AppEnv, Env } from '../types'

/** True when the Discord ID is listed in ADMIN_DISCORD_IDS (comma- or space-separated). */
export function isAdminId(env: Env, discordId: string): boolean {
  const ids = (env.ADMIN_DISCORD_IDS ?? '').split(/[\s,]+/).filter(Boolean)
  return ids.includes(discordId)
}

/** 403 unless the session (set by `requireSession`) belongs to an admin. */
export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (!isAdminId(c.env, c.get('discordId'))) return c.json({ error: 'Admins only' }, 403)
  return next()
}
