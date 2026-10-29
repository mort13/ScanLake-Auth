import type { Env } from './types'

const ROOT_DOMAIN = 'scanlake.rocks'

/**
 * True when `url` (an Origin header or a full URL) belongs to a ScanLake app:
 * https://scanlake.rocks or any https://*.scanlake.rocks, plus http://localhost
 * when ALLOW_LOCALHOST is on. Used for CORS, the login `return_to`, and the
 * Origin check on cookie-authenticated writes.
 */
export function isAllowedOrigin(url: string | null | undefined, env: Env): boolean {
  if (!url) return false
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  if (parsed.username || parsed.password) return false

  const host = parsed.hostname
  if (parsed.protocol === 'https:' && (host === ROOT_DOMAIN || host.endsWith(`.${ROOT_DOMAIN}`))) {
    return true
  }
  return (
    env.ALLOW_LOCALHOST === 'true' &&
    parsed.protocol === 'http:' &&
    (host === 'localhost' || host === '127.0.0.1')
  )
}
