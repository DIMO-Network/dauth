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
    audience   TEXT[],                     -- requested `aud` bound at challenge time; NULL = default
    scopes     TEXT[]      NOT NULL,       -- the token's scopes, bound at challenge time
    jkt        TEXT        NOT NULL        -- thumbprint of the DPoP key the token is bound to
);

-- Supports the janitor's range delete of expired rows.
CREATE INDEX IF NOT EXISTS nonce_challenges_expires_at_idx
    ON nonce_challenges (expires_at);
