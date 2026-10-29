/** The only native client allowed to use the desktop login. */
export const DESKTOP_CLIENT_ID = 'scanlake-desktop'

// RFC 8252 §7.3 loopback redirect, matched on the raw string so URL parsing can't
// normalize something else into it (e.g. `127.1`, `LOCALHOST`, `:080`). Rejects
// userinfo, query, fragment, `localhost` and any other path by construction.
const LOOPBACK_REDIRECT_RE = /^http:\/\/(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{3,4})\/callback$/
const MIN_PORT = 1024
const MAX_PORT = 65535

export function isAllowedClientId(clientId: unknown): clientId is string {
  return clientId === DESKTOP_CLIENT_ID
}

/** True for `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback` with port 1024-65535. */
export function isAllowedRedirectUri(uri: unknown): uri is string {
  if (typeof uri !== 'string') return false
  const match = LOOPBACK_REDIRECT_RE.exec(uri)
  if (!match) return false
  const port = Number(match[1])
  return port >= MIN_PORT && port <= MAX_PORT
}
