-- Desktop / native-app login (RFC 8252 loopback redirect + PKCE).
-- 'cookie' sessions come from the web login and are read from `sl_session`;
-- 'desktop' sessions are bearer tokens held by a desktop app and are only read from `Authorization`.
ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'cookie' CHECK (kind IN ('cookie', 'desktop'));
-- The desktop client id that holds the token; NULL for cookie sessions
ALTER TABLE sessions ADD COLUMN client TEXT;
-- When a desktop token was last used (updated at most hourly); NULL for cookie sessions
ALTER TABLE sessions ADD COLUMN last_used_at INTEGER;

-- One-time authorization codes, exchanged at POST /desktop/token. Only the SHA-256 of the code is stored.
CREATE TABLE desktop_codes (
  code_hash      TEXT PRIMARY KEY,
  discord_id     TEXT NOT NULL REFERENCES accounts (discord_id) ON DELETE CASCADE,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX desktop_codes_by_expiry ON desktop_codes (expires_at);
