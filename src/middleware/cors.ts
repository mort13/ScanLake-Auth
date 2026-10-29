import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'
import type { AppEnv, Env } from '../types'
import { isAllowedOrigin } from '../origins'

/**
 * Credentialed CORS for ScanLake apps only: the session cookie is sent with
 * `fetch(..., { credentials: 'include' })`, which needs the exact origin echoed back.
 */
export const corsMiddleware = cors({
  origin: (origin, c) => (isAllowedOrigin(origin, c.env as Env) ? origin : null),
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
  maxAge: 86400,
})

/**
 * CSRF guard for cookie-authenticated writes: browsers always send Origin on
 * POST/PUT/DELETE, so anything not coming from a ScanLake page is refused.
 */
export const originGuard: MiddlewareHandler<AppEnv> = async (c, next) => {
  const method = c.req.method
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return next()
  if (!isAllowedOrigin(c.req.header('Origin'), c.env)) {
    return c.json({ error: 'Forbidden origin' }, 403)
  }
  return next()
}
