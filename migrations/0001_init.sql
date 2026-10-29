-- One row per Discord user who has logged in. Only what the `identify` scope returns is kept: no email.
CREATE TABLE accounts (
  discord_id      TEXT PRIMARY KEY,
  username        TEXT NOT NULL,
  global_name     TEXT,
  avatar          TEXT,
  -- The ScanLake userId every device switches to after login
  primary_user_id TEXT,
  -- Capture profile, restored on a device after a cache wipe
  user_name       TEXT NOT NULL DEFAULT '',
  org             TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

-- ScanLake userIds linked to an account. The primary key means an ID belongs to at most one account.
CREATE TABLE user_ids (
  user_id    TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL REFERENCES accounts (discord_id) ON DELETE CASCADE,
  linked_at  INTEGER NOT NULL
);
CREATE INDEX user_ids_by_account ON user_ids (discord_id);

-- Login sessions. Only the SHA-256 of the cookie token is stored.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL REFERENCES accounts (discord_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_by_account ON sessions (discord_id);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);
