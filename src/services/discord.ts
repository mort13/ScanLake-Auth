import type { Env } from '../types'

const DISCORD_API = 'https://discord.com/api/v10'
const DISCORD_AUTHORIZE = 'https://discord.com/oauth2/authorize'

/** The fields of `GET /users/@me` we keep. The `identify` scope never includes an email. */
export interface DiscordUser {
  id: string
  username: string
  global_name: string | null
  avatar: string | null
}

function redirectUri(env: Env): string {
  return `${env.PUBLIC_URL}/callback`
}

export function authorizeUrl(env: Env, state: string): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: env.DISCORD_CLIENT_ID,
    scope: 'identify',
    redirect_uri: redirectUri(env),
    state,
    // Skip the consent screen when the user already authorized the app
    prompt: 'none',
  })
  return `${DISCORD_AUTHORIZE}?${params}`
}

/** Exchanges the authorization code for an access token. */
export async function exchangeCode(env: Env, code: string): Promise<string> {
  const res = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri(env),
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
    }),
  })
  if (!res.ok) throw new Error(`Discord token exchange failed (${res.status})`)
  const data = await res.json<{ access_token: string }>()
  return data.access_token
}

export async function fetchUser(accessToken: string): Promise<DiscordUser> {
  const res = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  if (!res.ok) throw new Error(`Discord user lookup failed (${res.status})`)
  const user = await res.json<DiscordUser>()
  return { id: user.id, username: user.username, global_name: user.global_name, avatar: user.avatar }
}

/** The token is only needed once to identify the user, so it is revoked right after. */
export async function revokeToken(env: Env, accessToken: string): Promise<void> {
  await fetch(`${DISCORD_API}/oauth2/token/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      token: accessToken,
      token_type_hint: 'access_token',
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
    }),
  })
}

export function avatarUrl(discordId: string, avatar: string | null): string | null {
  return avatar ? `https://cdn.discordapp.com/avatars/${discordId}/${avatar}.png?size=64` : null
}
