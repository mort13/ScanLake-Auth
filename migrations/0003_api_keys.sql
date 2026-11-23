-- Gateway API keys that logged-in users create for themselves (ScanLake Dashboard, /API tab).
-- Only the SHA-256 of the token is stored. The Gateway reads the KV entry `ukey:<key_hash>`
-- (namespace API_KEYS) that is written next to each active row and deleted on revoke.
CREATE TABLE api_keys (
  key_hash   TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL REFERENCES accounts (discord_id) ON DELETE CASCADE,
  -- The account's primary ScanLake userId when the key was made; NULL if none was linked yet
  user_id    TEXT,
  label      TEXT NOT NULL DEFAULT '',
  -- First characters of the token, shown in lists (e.g. "slk_1a2b3c4d")
  prefix     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  -- Who revoked it: 'user', 'admin' or 'blocked' (the account was blocked)
  revoked_by TEXT
);
CREATE INDEX api_keys_by_account ON api_keys (discord_id);

-- Gateway API tier of the account: 'verified' for every Discord login, 'trusted' or 'blocked' set by an admin
ALTER TABLE accounts ADD COLUMN api_tier TEXT NOT NULL DEFAULT 'verified'
  CHECK (api_tier IN ('verified', 'trusted', 'blocked'));
