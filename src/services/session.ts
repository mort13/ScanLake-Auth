import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import type { AppEnv, Env, SessionKind } from '../types'

export const SESSION_COOKIE = 'sl_session'
export const SESSION_TTL_S = 90 * 86400
// Sessions are extended on use once fewer than this many seconds are left
const RENEW_BELOW_S = 30 * 86400
// A desktop session's last_used_at is refreshed at most this often, to keep reads write-free
const LAST_USED_RESOLUTION_S = 3600

// `Authorization: Bearer <randomToken()>`; the scheme is case-insensitive (RFC 7235)
const BEARER_RE = /^bearer ([A-Za-z0-9_-]{43})$/i

const encoder = new TextEncoder()

export function nowS(): number {
  return Math.floor(Date.now() / 1000)
}

/** Base64url without padding (RFC 4648 §5). */
export function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Random URL-safe token with `bytes` bytes of entropy. */
export function randomToken(bytes = 32): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)))
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function cookieDomain(env: Env): string | undefined {
  return env.COOKIE_DOMAIN || undefined
}

function setSessionCookie(c: Context<AppEnv>, token: string) {
  setCookie(c, SESSION_COOKIE, token, {
    domain: cookieDomain(c.env),
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: SESSION_TTL_S,
  })
}

export function clearSessionCookie(c: Context<AppEnv>) {
  deleteCookie(c, SESSION_COOKIE, { domain: cookieDomain(c.env), path: '/', secure: true })
}

/** Starts a session for the account and sets the shared cookie. */
export async function createSession(c: Context<AppEnv>, discordId: string): Promise<void> {
  const token = randomToken()
  const now = nowS()
  await c.env.AUTH_DB.prepare(
    'INSERT INTO sessions (token_hash, discord_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
  )
    .bind(await sha256Hex(token), discordId, now, now + SESSION_TTL_S)
    .run()
  setSessionCookie(c, token)
}

/** Starts a desktop session for the account and returns its bearer token. */
export async function createBearerSession(
  db: D1Database,
  discordId: string,
  client: string,
): Promise<{ token: string; expiresIn: number }> {
  const token = randomToken()
  const now = nowS()
  await db
    .prepare(
      `INSERT INTO sessions (token_hash, discord_id, created_at, expires_at, kind, client, last_used_at)
       VALUES (?, ?, ?, ?, 'desktop', ?, ?)`,
    )
    .bind(await sha256Hex(token), discordId, now, now + SESSION_TTL_S, client, now)
    .run()
  return { token, expiresIn: SESSION_TTL_S }
}

/**
 * The credential the request carries. An `Authorization` header always wins and is
 * read alone: no cookie fallback, and anything but `Bearer <token>` means no session.
 * That keeps the cookie out of every request that skips the Origin check for bearers.
 */
function requestCredential(c: Context<AppEnv>): { kind: SessionKind; token: string } | null {
  const authorization = c.req.header('Authorization')
  if (authorization !== undefined) {
    const match = BEARER_RE.exec(authorization)
    return match ? { kind: 'desktop', token: match[1] } : null
  }
  const token = getCookie(c, SESSION_COOKIE)
  return token ? { kind: 'cookie', token } : null
}

/**
 * The request's session, or null when there is no valid one. A token only counts
 * for its own kind (a cookie token sent as a bearer is refused, and vice versa).
 * A session close to expiry is extended, so active users stay logged in.
 */
export async function readSession(
  c: Context<AppEnv>,
): Promise<{ discordId: string; kind: SessionKind } | null> {
  const credential = requestCredential(c)
  if (!credential) return null

  const hash = await sha256Hex(credential.token)
  const row = await c.env.AUTH_DB.prepare(
    'SELECT discord_id, expires_at, last_used_at FROM sessions WHERE token_hash = ? AND kind = ?',
  )
    .bind(hash, credential.kind)
    .first<{ discord_id: string; expires_at: number; last_used_at: number | null }>()

  const now = nowS()
  if (!row || row.expires_at <= now) return null

  const renew = row.expires_at - now < RENEW_BELOW_S
  if (credential.kind === 'cookie') {
    if (renew) {
      await c.env.AUTH_DB.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?')
        .bind(now + SESSION_TTL_S, hash)
        .run()
      setSessionCookie(c, credential.token)
    }
  } else if (renew || (row.last_used_at ?? 0) <= now - LAST_USED_RESOLUTION_S) {
    // A bearer token is renewed in D1 only; the app keeps using the same token
    await c.env.AUTH_DB.prepare('UPDATE sessions SET expires_at = ?, last_used_at = ? WHERE token_hash = ?')
      .bind(renew ? now + SESSION_TTL_S : row.expires_at, now, hash)
      .run()
  }
  return { discordId: row.discord_id, kind: credential.kind }
}

/**
 * Deletes the request's session (if any): the bearer token's when an `Authorization`
 * header is sent, else the cookie's, which is also cleared.
 */
export async function endSession(c: Context<AppEnv>): Promise<void> {
  const credential = requestCredential(c)
  if (credential) {
    await c.env.AUTH_DB.prepare('DELETE FROM sessions WHERE token_hash = ? AND kind = ?')
      .bind(await sha256Hex(credential.token), credential.kind)
      .run()
  }
  if (c.req.header('Authorization') === undefined) clearSessionCookie(c)
}

/** Daily cleanup: expired sessions of both kinds and expired desktop login codes. */
export async function deleteExpiredSessions(db: D1Database): Promise<void> {
  const now = nowS()
  await db.batch([
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now),
    db.prepare('DELETE FROM desktop_codes WHERE expires_at <= ?').bind(now),
  ])
}
