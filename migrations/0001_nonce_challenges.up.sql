-- 0001_nonce_challenges: the Postgres-backed challenge store.
--
-- dauth self-applies this DDL at startup (see internal/nonce/schema.sql, which
-- this mirrors), so a fresh database needs no manual migration. This file exists
-- for operators who prefer to manage schema out of band — apply it before
-- starting dauth and the embedded CREATE ... IF NOT EXISTS becomes a no-op.

CREATE TABLE IF NOT EXISTS nonce_challenges (
    nonce      TEXT        PRIMARY KEY,
    message    TEXT        NOT NULL,
    address    BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS nonce_challenges_expires_at_idx
    ON nonce_challenges (expires_at);
