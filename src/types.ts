export interface Env {
  AUTH_DB: D1Database
  DISCORD_CLIENT_ID: string
  DISCORD_CLIENT_SECRET: string
  /** Public base URL of this worker; Discord redirects to `${PUBLIC_URL}/callback`. */
  PUBLIC_URL: string
  /** Domain the session cookie is set on so all subdomains share it. Empty = host-only cookie. */
  COOKIE_DOMAIN: string
  /** "true" also accepts http://localhost origins (local dev only). */
  ALLOW_LOCALHOST: string
  /** Limits the desktop code exchange (per IP) and code issuing (per account). Optional. */
  DESKTOP_RATE_LIMIT?: RateLimit
}

/** 'cookie' = web login (`sl_session` cookie), 'desktop' = bearer token held by a desktop app. */
export type SessionKind = 'cookie' | 'desktop'

export type AppEnv = {
  Bindings: Env
  Variables: { discordId: string; sessionKind: SessionKind }
}

/** What `GET /api/me` returns: everything an app needs about the logged-in user. */
export interface Me {
  discord: {
    id: string
    username: string
    globalName: string | null
    avatarUrl: string | null
  }
  /** The ScanLake userId every device switches to; null until the first ID is linked. */
  primaryUserId: string | null
  /** All ScanLake userIds linked to this account, oldest first. */
  userIds: string[]
  /** Capture profile fields, so a wiped device gets them back. */
  profile: { userName: string; org: string }
}
