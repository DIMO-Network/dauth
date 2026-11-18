-- Single-table schema for the Postgres-backed challenge store. Embedded into
-- the binary and applied idempotently at startup (Dex-style self-bootstrap), so
-- a fresh database needs no out-of-band migration step. This file is the sole
-- source of truth for the schema.
CREATE TABLE IF NOT EXISTS nonce_challenges (
    nonce      TEXT        PRIMARY KEY,    -- the random nonce; also in the challenge text
    message    TEXT        NOT NULL,       -- the challenge text the DID's key signs
    did        TEXT        NOT NULL,       -- DID expected to sign
    expires_at TIMESTAMPTZ NOT NULL,       -- absolute expiry; rows past this are swept
    audience   TEXT[]                      -- requested `aud` bound at challenge time; NULL = default
);

-- Supports the janitor's range delete of expired rows.
CREATE INDEX IF NOT EXISTS nonce_challenges_expires_at_idx
    ON nonce_challenges (expires_at);
