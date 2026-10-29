import { cors } from 'hono/cors'
import type { MiddlewareHandler } from 'hono'
import type { AppEnv, Env } from '../types'
import { isAllowedOrigin } from '../origins'

/**
 * Credentialed CORS for ScanLake apps only: the session cookie is sent with
 * `fetch(..., { credentials: 'include' })`, which needs the exact origin echoed back.
 * `Authorization` is deliberately not an allowed header, so no web page can send
 * a desktop bearer token cross-origin.
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
 * POST/PUT/DELETE, so anything not coming from a ScanLake page (or this worker's
 * own pages, i.e. the desktop Allow/Deny form) is refused.
 * Requests with an `Authorization` header are exempt: the cookie is never read for
 * them, so there is no ambient credential to forge. So is the desktop code exchange,
 * which is called by the desktop app (no Origin) and authenticated by code + PKCE.
 */
export const originGuard: MiddlewareHandler<AppEnv> = async (c, next) => {
  const method = c.req.method
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return next()
  if (c.req.header('Authorization') !== undefined) return next()
  if (method === 'POST' && c.req.path === '/desktop/token') return next()
  const origin = c.req.header('Origin')
  if (!isAllowedOrigin(origin, c.env) && !isSameOrigin(origin, c.req.url)) {
    return c.json({ error: 'Forbidden origin' }, 403)
  }
  return next()
}

/**
 * True for a request from one of this worker's own pages. In production that origin
 * already passes `isAllowedOrigin`; under `wrangler dev` both the request URL and a
 * same-origin Origin are rewritten to `http://auth.scanlake.rocks`, which does not.
 */
function isSameOrigin(origin: string | undefined, requestUrl: string): boolean {
  return origin !== undefined && origin === new URL(requestUrl).origin
}
