-- LP Planner — initial D1 schema
-- Conventions: ids TEXT (crypto.randomUUID), timestamps INTEGER ms since epoch (UTC).

-- One row per person. `seq` is a per-user change counter: every saved document
-- gets the next number, so devices can ask "what changed since #N?" cheaply.
CREATE TABLE users (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  name        TEXT,
  picture     TEXT,
  seq         INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);

-- App sessions issued by the Worker after Google sign-in. Only the SHA-256 hash is stored.
CREATE TABLE sessions (
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  user_agent    TEXT
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- Google tokens for Calendar, AES-GCM encrypted with TOKEN_ENC_KEY.
-- The refresh token never leaves the Worker; short-lived access tokens are handed
-- only to a signed-in session.
CREATE TABLE google_tokens (
  user_id            TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  refresh_enc        TEXT,
  refresh_iv         TEXT,
  access_enc         TEXT,
  access_iv          TEXT,
  access_expires_at  INTEGER,
  scope              TEXT,
  updated_at         INTEGER NOT NULL
);

-- All planner data. The app's existing data shapes are stored unchanged, split into
-- small documents (one week, one page, one fitness day, one month of habit data, …).
--   version  increments on every write; a save must name the version it was based on
--   seq      users.seq at the time of the write (drives /api/changes)
--   deleted  tombstone so other devices learn about deletions
CREATE TABLE docs (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  collection  TEXT NOT NULL,
  doc_id      TEXT NOT NULL,
  data        TEXT NOT NULL,
  version     INTEGER NOT NULL,
  seq         INTEGER NOT NULL,
  deleted     INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, collection, doc_id)
);
-- "What changed since #N" reads only the changed rows (keeps D1 row-read counts tiny).
CREATE INDEX idx_docs_user_seq ON docs(user_id, seq);
