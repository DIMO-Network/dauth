-- Single-table schema for the Postgres-backed challenge store. Embedded into
-- the binary and applied idempotently at startup (Dex-style self-bootstrap), so
-- a fresh database needs no out-of-band migration step. This file is the sole
-- source of truth for the schema.
CREATE TABLE IF NOT EXISTS nonce_challenges (
    nonce      TEXT        PRIMARY KEY,    -- the random nonce; also the SIWE nonce
    message    TEXT        NOT NULL,       -- canonical EIP-4361 message the wallet signs
    address    BYTEA       NOT NULL,       -- 20-byte Ethereum address expected to sign
    expires_at TIMESTAMPTZ NOT NULL,       -- absolute expiry; rows past this are swept
    audience   TEXT[]                      -- requested `aud` bound at challenge time; NULL = default
);

-- Additive column for tables created before audience binding existed. The
-- schema self-bootstraps on every startup, so this keeps an existing deployment
-- in sync without an out-of-band migration.
ALTER TABLE nonce_challenges ADD COLUMN IF NOT EXISTS audience TEXT[];

-- Supports the janitor's range delete of expired rows.
CREATE INDEX IF NOT EXISTS nonce_challenges_expires_at_idx
    ON nonce_challenges (expires_at);
