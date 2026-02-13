-- Authenticated identities.
CREATE TABLE IF NOT EXISTS authn(
  key_id TEXT PRIMARY KEY NOT NULL,
  public_key TEXT UNIQUE NOT NULL,
  nonce TEXT UNIQUE NOT NULL,
  time_authenticated TEXT NOT NULL,
  time_revoked TEXT
) STRICT;

-- WARNING: Destructive!
ALTER TABLE jobs DROP COLUMN interactive;
ALTER TABLE jobs ADD COLUMN interactive TEXT REFERENCES authn(key_id);

-- Unauthenticated challenges.
CREATE TABLE IF NOT EXISTS challenges(
  nonce TEXT PRIMARY KEY NOT NULL
) STRICT;
