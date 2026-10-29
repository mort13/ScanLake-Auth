# ScanLake Auth

Optional Discord login shared by every ScanLake app on `*.scanlake.rocks`.

- Ties the anonymous ScanLake **userId** (created by Capture) to a Discord account, so the ID can be restored after a cache wipe or on another PC.
- Uses only Discord's `identify` scope: the Discord ID, username, display name and avatar. **No email** is requested or stored. The Discord access token is used once to identify the user and then revoked.
- One login for all apps: the session cookie `sl_session` is set on `Domain=scanlake.rocks` (HttpOnly, Secure, SameSite=Lax, 90 days, extended while used).

Cloudflare Worker (Hono) at `https://auth.scanlake.rocks` with a D1 database.

## How an app uses it

```js
const AUTH = 'https://auth.scanlake.rocks'

// Who is logged in? 401 = nobody.
const res = await fetch(`${AUTH}/api/me`, { credentials: 'include' })
const me = res.ok ? await res.json() : null

// Log in (browser navigation; comes back to the current page)
location.href = `${AUTH}/login?return_to=${encodeURIComponent(location.href)}`

// Log out of every ScanLake app
await fetch(`${AUTH}/logout`, { method: 'POST', credentials: 'include' })
```

A new app only has to be served from a `*.scanlake.rocks` subdomain; nothing changes here.

## Endpoints

| Route | Does |
|---|---|
| `GET /login?return_to=<url>` | Starts the Discord login. `return_to` must be a `https://*.scanlake.rocks` URL. |
| `GET /callback` | Discord redirects here. Creates the account and session, then redirects to `return_to`. |
| `POST /logout` | Ends the session (204). |
| `GET /api/me` | 401 when logged out, else `{ discord: { id, username, globalName, avatarUrl }, primaryUserId, userIds, profile: { userName, org } }`. |
| `POST /api/me/user-ids` `{ userId }` | Links a ScanLake userId (UUID v4). The first linked ID becomes the primary. 409 if another account owns it, 422 above 20 IDs. Returns the updated `me`. |
| `PUT /api/me/profile` `{ userName, org }` | Stores the Capture profile (max 64 chars each). Returns the updated `me`. |
| `DELETE /api/me` | Unlinks Discord: deletes the account, its linked IDs and its sessions (204). |

Writes (`POST`/`PUT`/`DELETE`) are refused unless the `Origin` header is a ScanLake app.

**Known limit:** userIds are public in the scan data, so the first account to link an ID owns it. Fix a wrong link by hand:

```bash
npx wrangler d1 execute scanlake-auth --remote --command "DELETE FROM user_ids WHERE user_id = '<uuid>'"
```

## Setup

1. **Discord application:** in the [Discord Developer Portal](https://discord.com/developers/applications), create an application. Under **OAuth2 → Redirects**, add `https://auth.scanlake.rocks/callback` (and `http://localhost:8788/callback` for local dev). Copy the **Client ID** into `DISCORD_CLIENT_ID` in `wrangler.toml` and keep the **Client Secret** for step 4.
2. **Database:** `npx wrangler d1 create scanlake-auth`, then put the printed `database_id` into `wrangler.toml`.
3. **Tables:** `npm run db:migrate`
4. **Secret:** `npx wrangler secret put DISCORD_CLIENT_SECRET`
5. **Deploy:** `npm run deploy`. The `auth.scanlake.rocks` custom domain is created from `wrangler.toml`.

## Local development

```bash
npm install
cp .dev.vars.example .dev.vars   # fill in DISCORD_CLIENT_SECRET (the client ID comes from wrangler.toml)
npm run db:migrate:local
npm run dev                      # http://localhost:8788
```

Capture and Dashboard point at it through `VITE_AUTH_URL=http://localhost:8788` in their `.env.development.local` (dev server only; `vite build` ignores that file, so deploys use `https://auth.scanlake.rocks`). Locally the cookie is host-only on `localhost`; cookies ignore ports, so Capture and Dashboard on other localhost ports share the login just like the subdomains do in production.
