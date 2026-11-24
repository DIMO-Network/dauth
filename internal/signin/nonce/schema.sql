-- Single-table schema for the Postgres-backed challenge store. Embedded into
-- the binary and applied idempotently at startup (Dex-style self-bootstrap), so
-- a fresh database needs no out-of-band migration step. This file is the sole
-- source of truth for the schema.

-- Challenges live for minutes, so a table from before scopes and keys holds
-- nothing worth keeping: drop it and start over.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'nonce_challenges')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'nonce_challenges' AND column_name = 'jkt') THEN
        DROP TABLE nonce_challenges;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS nonce_challenges (
    nonce      TEXT        PRIMARY KEY,    -- the random nonce; also in the challenge text
    message    TEXT        NOT NULL,       -- the challenge text the DID's key signs
    did        TEXT        NOT NULL,       -- DID expected to sign
    expires_at TIMESTAMPTZ NOT NULL,       -- absolute expiry; rows past this are swept
    audience   TEXT[],                     -- resolved `aud` (default applied), bound at challenge time
    scopes     TEXT[]      NOT NULL,       -- the token's scopes, bound at challenge time
    jkt        TEXT        NOT NULL,       -- thumbprint of the DPoP key the token is bound to
    client_key TEXT        NOT NULL DEFAULT ''  -- rate-limit key of the client that asked; budgets rows per client
);

-- A table from before the per-client budget gains the column; its rows count
-- as one client ('') until they expire. ALTER TABLE takes ACCESS EXCLUSIVE
-- even when the column exists, queued behind every open transaction on the
-- table and blocking every query after it, so it runs only when the column
-- is missing. IF NOT EXISTS stays on the ALTER in case two starts both see
-- the column missing.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = current_schema()
                     AND table_name = 'nonce_challenges' AND column_name = 'client_key') THEN
        ALTER TABLE nonce_challenges ADD COLUMN IF NOT EXISTS client_key TEXT NOT NULL DEFAULT '';
    END IF;
END $$;

-- Supports the janitor's range delete of expired rows.
CREATE INDEX IF NOT EXISTS nonce_challenges_expires_at_idx
    ON nonce_challenges (expires_at);

-- Supports Put's trim of a client's oldest rows past its budget.
CREATE INDEX IF NOT EXISTS nonce_challenges_client_key_idx
    ON nonce_challenges (client_key, expires_at);
