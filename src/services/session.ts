import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import type { AppEnv, Env } from '../types'

export const SESSION_COOKIE = 'sl_session'
const SESSION_TTL_S = 90 * 86400
// Sessions are extended on use once fewer than this many seconds are left
const RENEW_BELOW_S = 30 * 86400

const encoder = new TextEncoder()

export function nowS(): number {
  return Math.floor(Date.now() / 1000)
}

/** Random URL-safe token with `bytes` bytes of entropy. */
export function randomToken(bytes = 32): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes))
  let binary = ''
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function sha256Hex(value: string): Promise<string> {
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

/**
 * The Discord ID of the request's session, or null when there is no valid one.
 * A session close to expiry is extended, so active users stay logged in.
 */
export async function readSession(c: Context<AppEnv>): Promise<string | null> {
  const token = getCookie(c, SESSION_COOKIE)
  if (!token) return null

  const hash = await sha256Hex(token)
  const row = await c.env.AUTH_DB.prepare(
    'SELECT discord_id, expires_at FROM sessions WHERE token_hash = ?',
  )
    .bind(hash)
    .first<{ discord_id: string; expires_at: number }>()

  const now = nowS()
  if (!row || row.expires_at <= now) return null

  if (row.expires_at - now < RENEW_BELOW_S) {
    await c.env.AUTH_DB.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?')
      .bind(now + SESSION_TTL_S, hash)
      .run()
    setSessionCookie(c, token)
  }
  return row.discord_id
}

/** Deletes the request's session (if any) and clears the cookie. */
export async function endSession(c: Context<AppEnv>): Promise<void> {
  const token = getCookie(c, SESSION_COOKIE)
  if (token) {
    await c.env.AUTH_DB.prepare('DELETE FROM sessions WHERE token_hash = ?')
      .bind(await sha256Hex(token))
      .run()
  }
  clearSessionCookie(c)
}

export async function deleteExpiredSessions(db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(nowS()).run()
}
