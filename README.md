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
| `DELETE /api/me` | Unlinks Discord: deletes the account, its linked IDs, its sessions (web and desktop) and its Gateway API keys (204). |
| `GET /api/me/api-keys` | `{ tier, limits: { maxKeys, perMinute, perDay }, issuing, keys: [{ id, prefix, label, createdAt, revokedAt, revokedBy }] }`. See [Gateway API keys](#gateway-api-keys). |
| `POST /api/me/api-keys` `{ label }` | Creates a key (201 `{ token, key }`; the token is only in this response). 403 when paused or blocked, 409 at the tier's key limit, 429 above 5 key changes per minute. |
| `DELETE /api/me/api-keys/:id` | Revokes one of the account's keys (204, 404 if unknown). |
| `/api/admin/*` | Admin panel API, see [Admin](#admin). |
| `GET /desktop/authorize` | Desktop login, opened in the system browser. See [Desktop / native apps](#desktop--native-apps). |
| `POST /desktop/authorize` | The Allow/Deny form on the desktop confirmation page. |
| `POST /desktop/token` | The desktop app exchanges its one-time code for a bearer token. |

Writes (`POST`/`PUT`/`DELETE`) are refused unless the `Origin` header is a ScanLake app. Exceptions: requests with an `Authorization` header (the cookie is never read for those, so there is nothing to forge) and `POST /desktop/token`.

**Known limit:** userIds are public in the scan data, so the first account to link an ID owns it. Fix a wrong link by hand:

```bash
npx wrangler d1 execute scanlake-auth --remote --command "DELETE FROM user_ids WHERE user_id = '<uuid>'"
```

## Desktop / native apps

ScanLake Desktop can't use the cookie, so it logs in through the system browser and gets a **bearer token** ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) loopback redirect + [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE, `S256` only). The only client id is `scanlake-desktop`; there is no client secret. Nothing changes in the Discord portal: the browser half is the normal web login.

1. The app makes a random `code_verifier` (43-128 chars of `A-Z a-z 0-9 - . _ ~`), its `code_challenge = BASE64URL(SHA256(verifier))` without padding, and a random `state`, and listens on `http://127.0.0.1:<free port>/callback` (or `http://[::1]:<port>/callback`).
2. It opens `GET /desktop/authorize?response_type=code&client_id=scanlake-desktop&redirect_uri=<loopback URL>&state=<state>&code_challenge=<challenge>&code_challenge_method=S256` in the browser.
3. Not logged in on the web: the browser goes through `/login` (Discord) and comes back. Logged in: a page asks *"Sign in to ScanLake Desktop as Name (@username)?"*.
4. **Allow** redirects (303) to `<redirect_uri>?code=<code>&state=<state>`; **Deny** to `<redirect_uri>?error=access_denied&state=<state>`. The code is valid for 120 seconds and once.
5. The app checks `state` and posts the code (form-encoded, no `Origin` needed) to `POST /desktop/token`:
   `grant_type=authorization_code&code=<code>&code_verifier=<verifier>&redirect_uri=<same loopback URL>&client_id=scanlake-desktop`
   → `200 { "access_token": "<43 chars>", "token_type": "Bearer", "expires_in": 7776000 }`
6. It calls `/api/me*` and `POST /logout` with `Authorization: Bearer <access_token>`.

| Endpoint | Errors |
|---|---|
| `GET`/`POST /desktop/authorize` | Unknown `client_id` or a `redirect_uri` that isn't `http://127.0.0.1:<1024-65535>/callback` / `http://[::1]:<port>/callback` (no `localhost`, query, fragment or userinfo): 400 error page, **never** a redirect. Any other bad parameter (`response_type`, `state` missing or not 1-256 printable ASCII chars, `code_challenge`, `code_challenge_method` not `S256`): redirect with `error=invalid_request` (and `state` if it was valid). 429 page above 20 codes per minute per account. |
| `POST /desktop/token` | 400 `{ "error": "invalid_request" }` for a missing/malformed parameter, 400 `{ "error": "invalid_grant" }` for an unknown, used or expired code, a different `redirect_uri`/`client_id` or a wrong verifier. A code is burned by the first exchange attempt, successful or not. 429 `{ "error": "rate_limited" }` above 20 requests per minute per IP. |

**Bearer rules**

- An `Authorization` header always wins: only `Bearer <43-char token>` is read (scheme case-insensitive), there is no cookie fallback, and anything malformed is 401. A web cookie token is never accepted as a bearer token and vice versa (`sessions.kind` is `cookie` or `desktop`).
- Desktop sessions last 90 days and are extended in D1 (same token) while used, like the cookie. `expires_in` is the initial lifetime only: treat a 401 as "log in again".
- Browsers can't send the header cross-origin: CORS only allows `Content-Type`.
- The authorize, token and Allow/Deny responses are `Cache-Control: no-store`; the pages are never framed (`X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`) and send `Referrer-Policy: same-origin` (`no-referrer` would make browsers send `Origin: null` on the Allow/Deny POST, which the Origin guard refuses).
- Requests are rate-limited through the `DESKTOP_RATE_LIMIT` binding in `wrangler.toml` (optional: without the binding nothing is limited).

**Revoking desktop sessions**

- From the app: `POST /logout` with the bearer token deletes that one session (the web cookie stays).
- `DELETE /api/me` (web or desktop) deletes the account with all its web and desktop sessions.
- By hand, e.g. after a lost PC:

```bash
# List desktop sessions of an account
npx wrangler d1 execute scanlake-auth --remote --command "SELECT client, datetime(created_at, 'unixepoch') AS created, datetime(last_used_at, 'unixepoch') AS last_used, datetime(expires_at, 'unixepoch') AS expires FROM sessions WHERE kind = 'desktop' AND discord_id = '<discord id>'"
# Revoke all of them
npx wrangler d1 execute scanlake-auth --remote --command "DELETE FROM sessions WHERE kind = 'desktop' AND discord_id = '<discord id>'"
```

`last_used_at` is updated at most once an hour.

## Gateway API keys

Logged-in users create their own keys for [ScanLake Gateway](https://gateway.scanlake.rocks) in the Dashboard's `/API` tab. A key reads only the public derived files (manifest, consolidated scans and compositions, `results/*.parquet`); the Gateway enforces that.

- Token: `slk_` + 64 hex characters, shown once. D1 (`api_keys`) keeps only its SHA-256 and the first 12 characters.
- Each active key has a KV entry `ukey:<sha256>` in the `API_KEYS` namespace shared with the Gateway: `{ kind: "user", ownerId, discordId, tier, active, limits: [{ limit, windowMs }], rateLimit, rateLimitWindowMs, maxUploadBytes: 0, allowedOrigins: [], scopes: ["derived:public"], createdAt }`. `ownerId` is the account's primary ScanLake userId (or `discord:<id>`). ScanLake Store reads the same namespace, but only `apikey:*` with `sk_` tokens, so user keys can't upload.
- Revoking deletes the KV entry; the Gateway stops accepting the key within about a minute (KV caching).
- Tiers live in `src/apikeys/tiers.ts`. Limits count per account, shared by all its keys:

| Tier | Who | Active keys | Requests/min | Requests/day |
|---|---|---|---|---|
| `verified` | every Discord account (default) | 2 | 60 | 2,000 |
| `trusted` | set by an admin | 5 | 600 | 20,000 |
| `blocked` | set by an admin | 0, all keys revoked | – | – |

- Switch `config:user-keys` = `{ "issuing": bool, "serving": bool }` in the same KV (missing = both on): `issuing: false` stops new keys, `serving: false` makes the Gateway refuse every user key.

## Admin

Discord IDs in `ADMIN_DISCORD_IDS` (`wrangler.toml`, comma-separated) get `isAdmin: true` from `/api/me` and may call:

| Route | Does |
|---|---|
| `GET /api/admin/api-keys` | Every user key with its account (Discord ID, username, display name, ScanLake userId, tier) and usage over 30 days (`requests24h/7d/30d`, `bytes30d`, `limited30d`, `lastUsedAt`, `daily[]`), the Gateway's other keys by owner (`internal`), summary counts, `settings` and the tier table. |
| `POST /api/admin/api-keys/:id/revoke` | Revokes any key (204). |
| `PUT /api/admin/accounts/:discordId/tier` `{ tier }` | `verified`, `trusted` or `blocked`. Rewrites the KV entries of the account's keys; `blocked` revokes them. |
| `GET` / `PUT /api/admin/settings` `{ issuing?, serving? }` | The on/off switch. |

Usage comes from the Analytics Engine dataset `USAGE_DATASET` (default `scanlake_gateway_usage`) that the Gateway writes one data point per request to, read through the `ANALYTICS_SQL` binding (no API token needed). That binding is remote only: under `wrangler dev` it queries the real account, and in tests it's never called. When it fails, the list still works with `usageAvailable: false` and `usageError`.

## Setup

1. **Discord application:** in the [Discord Developer Portal](https://discord.com/developers/applications), create an application. Under **OAuth2 → Redirects**, add `https://auth.scanlake.rocks/callback` (and `http://localhost:8788/callback` for local dev). Copy the **Client ID** into `DISCORD_CLIENT_ID` in `wrangler.toml` and keep the **Client Secret** for step 4.
2. **Database:** `npx wrangler d1 create scanlake-auth`, then put the printed `database_id` into `wrangler.toml`.
3. **Tables:** `npm run db:migrate`
4. **Secret:** `npx wrangler secret put DISCORD_CLIENT_SECRET`
5. **Admin:** put your Discord ID into `ADMIN_DISCORD_IDS` in `wrangler.toml`.
6. **Deploy:** `npm run deploy`. The `auth.scanlake.rocks` custom domain is created from `wrangler.toml`.

## Local development

```bash
npm install
cp .dev.vars.example .dev.vars   # fill in DISCORD_CLIENT_SECRET (the client ID comes from wrangler.toml)
npm run db:migrate:local
npm run dev                      # http://localhost:8788
```

Capture and Dashboard point at it through `VITE_AUTH_URL=http://localhost:8788` in their `.env.development.local` (dev server only; `vite build` ignores that file, so deploys use `https://auth.scanlake.rocks`). Locally the cookie is host-only on `localhost`; cookies ignore ports, so Capture and Dashboard on other localhost ports share the login just like the subdomains do in production.

**Desktop app against local dev:** point ScanLake Desktop's auth base URL at `http://localhost:8788`. With `ALLOW_LOCALHOST=true` and `PUBLIC_URL=http://localhost:8788` in `.dev.vars`, `/desktop/authorize` sends the browser through the local `/login` and back. The app's redirect URI stays `http://127.0.0.1:<port>/callback` (never `localhost`). `wrangler dev` rewrites the request URL and a same-origin `Origin` to `http://auth.scanlake.rocks`; the Origin guard accepts a request's own origin, so the Allow/Deny form works locally too.

## Tests

```bash
npm test            # vitest in the Workers runtime (@cloudflare/vitest-plugin), D1 migrations applied in setup
npm run typecheck   # src and test
```

The tests seed accounts and sessions straight into D1, so they never call Discord.
