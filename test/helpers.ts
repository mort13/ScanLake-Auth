import { env, exports } from 'cloudflare:workers'
import { SESSION_COOKIE, SESSION_TTL_S, nowS, randomToken, sha256Hex } from '../src/services/session'
import type { SessionKind } from '../src/types'

export const BASE = 'https://auth.scanlake.rocks'
export const APP_ORIGIN = 'https://capture.scanlake.rocks'
export const CLIENT_ID = 'scanlake-desktop'
export const REDIRECT_URI = 'http://127.0.0.1:53682/callback'
export const STATE = 'xyz-state_123'
// RFC 7636 Appendix B
export const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
export const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

export const DISCORD_ID = '100000000000000001'

/** Sends a request to the worker; redirects are returned, not followed. */
export function call(path: string, init: RequestInit = {}): Promise<Response> {
  return exports.default.fetch(new Request(`${BASE}${path}`, { redirect: 'manual', ...init }))
}

export async function resetDb(): Promise<void> {
  const db = env.AUTH_DB
  await db.batch([
    db.prepare('DELETE FROM desktop_codes'),
    db.prepare('DELETE FROM sessions'),
    db.prepare('DELETE FROM user_ids'),
    db.prepare('DELETE FROM accounts'),
  ])
}

export async function seedAccount(
  discordId = DISCORD_ID,
  { username = 'miner', globalName = 'Rock Miner' }: { username?: string; globalName?: string | null } = {},
): Promise<void> {
  const now = nowS()
  await env.AUTH_DB.prepare(
    `INSERT INTO accounts (discord_id, username, global_name, avatar, created_at, updated_at)
     VALUES (?, ?, ?, NULL, ?, ?)`,
  )
    .bind(discordId, username, globalName, now, now)
    .run()
}

/** Inserts a session row and returns its token. */
export async function seedSession(
  discordId = DISCORD_ID,
  kind: SessionKind = 'cookie',
  expiresInS = SESSION_TTL_S,
): Promise<string> {
  const token = randomToken()
  const now = nowS()
  await env.AUTH_DB.prepare(
    `INSERT INTO sessions (token_hash, discord_id, created_at, expires_at, kind, client, last_used_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(token),
      discordId,
      now,
      now + expiresInS,
      kind,
      kind === 'desktop' ? CLIENT_ID : null,
      kind === 'desktop' ? now : null,
    )
    .run()
  return token
}

export async function sessionRow(token: string) {
  return env.AUTH_DB.prepare('SELECT * FROM sessions WHERE token_hash = ?')
    .bind(await sha256Hex(token))
    .first<{ discord_id: string; kind: string; client: string | null; expires_at: number; last_used_at: number | null }>()
}

export function cookieHeader(token: string): string {
  return `${SESSION_COOKIE}=${token}`
}

export function authorizeQuery(overrides: Record<string, string | null> = {}): string {
  const params: Record<string, string | null> = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state: STATE,
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    ...overrides,
  }
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) if (value !== null) query.set(key, value)
  return query.toString()
}

/** Submits the confirmation form (Allow by default) as the cookie session's browser would. */
export function postDecision(
  cookieToken: string | null,
  overrides: Record<string, string | null> = {},
  origin: string | null = BASE,
): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' }
  if (cookieToken) headers.Cookie = cookieHeader(cookieToken)
  if (origin) headers.Origin = origin
  return call('/desktop/authorize', {
    method: 'POST',
    headers,
    body: authorizeQuery({ decision: 'allow', ...overrides }),
  })
}

/** Runs Allow for the seeded cookie session and returns the issued code. */
export async function issueCode(cookieToken: string, overrides: Record<string, string | null> = {}): Promise<string> {
  const res = await postDecision(cookieToken, overrides)
  if (res.status !== 303) throw new Error(`authorize POST returned ${res.status}`)
  const code = new URL(res.headers.get('Location')!).searchParams.get('code')
  if (!code) throw new Error('no code in redirect')
  return code
}

export function exchange(fields: Record<string, string | null>, headers: Record<string, string> = {}): Promise<Response> {
  const body = new URLSearchParams()
  for (const [key, value] of Object.entries(fields)) if (value !== null) body.set(key, value)
  return call('/desktop/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
    body,
  })
}

export function tokenFields(code: string, overrides: Record<string, string | null> = {}) {
  return {
    grant_type: 'authorization_code',
    code,
    code_verifier: VERIFIER,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    ...overrides,
  }
}

export function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` }
}
