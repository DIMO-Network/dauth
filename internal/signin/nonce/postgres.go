package nonce

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

//go:embed schema.sql
var schema string

// Postgres is a Store backed by a single nonce_challenges table. Unlike the
// in-memory store it is shared across replicas, so a challenge issued by one
// dauth pod is consumable on any other — which is what lets dauth run more than
// one replica. Single-use consumption is a DELETE ... WHERE nonce AND jkt
// RETURNING, atomic even under concurrent /signin/token calls racing on the
// same nonce: exactly one caller gets the row, every other gets ErrNotFound,
// and a caller naming another key deletes nothing.
//
// There is no cap on the table as a whole, only per client: a client holds at
// most MaxPerClient rows, and a new one replaces that client's oldest, as in
// the in-memory store. A flood from many addresses therefore costs at most
// MaxPerClient small rows per address, on top of dauth's per-address rate
// limit on /signin/challenge (SIGNIN_RATE_LIMIT_PER_SECOND, per pod), and the
// janitor sweeps what expires.
type Postgres struct {
	db  *pgxpool.Pool
	now func() time.Time
	log zerolog.Logger
}

// schemaLockKey is the pg_advisory_xact_lock key that serializes schema
// bootstrap across replicas starting at once. It is a fixed, arbitrary
// constant ("dauthnce" in ASCII); anything else in the database that takes an
// advisory lock must not reuse it.
const schemaLockKey int64 = 0x64617574686e6365

// NewPostgres ensures the schema exists on db and starts a background janitor
// that evicts expired challenges until ctx is cancelled. The caller owns db's
// lifecycle (open and Close).
func NewPostgres(ctx context.Context, db *pgxpool.Pool, log zerolog.Logger) (*Postgres, error) {
	if err := ensureSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("ensuring nonce schema: %w", err)
	}
	p := &Postgres{db: db, now: time.Now, log: log}
	go p.janitor(ctx)
	return p, nil
}

// ensureSchema applies schema.sql under a transaction-scoped advisory lock.
// CREATE TABLE IF NOT EXISTS is not safe against itself: two replicas running
// it at once on a fresh database can both pass the existence check and one
// then fails on the catalog's unique index. The lock makes them take turns;
// it is released when the transaction ends.
func ensureSchema(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, schemaLockKey); err != nil {
		return fmt.Errorf("taking schema lock: %w", err)
	}
	if _, err := tx.Exec(ctx, schema); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Put inserts ch under id and, in the same statement, deletes the client's
// oldest rows past its newest MaxPerClient-1, so with the new row the client
// holds at most MaxPerClient. The delete sees the table as it was before the
// statement, so concurrent Puts from one client can each keep their own row
// and briefly leave it one over per concurrent call; the next Put trims it. A
// duplicate nonce (astronomically unlikely for 32 random bytes) surfaces as an
// error and the handler reports the challenge store unavailable.
func (p *Postgres) Put(ctx context.Context, id string, ch Challenge) error {
	_, err := p.db.Exec(ctx,
		`WITH trimmed AS (
		     DELETE FROM nonce_challenges WHERE nonce IN (
		         SELECT nonce FROM nonce_challenges WHERE client_key = $8
		         ORDER BY expires_at DESC, nonce DESC OFFSET $9))
		 INSERT INTO nonce_challenges (nonce, message, did, expires_at, audience, scopes, jkt, client_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, ch.Message, ch.DID, ch.ExpiresAt, ch.Audience, ch.Scopes, ch.JKT, ch.Client, MaxPerClient-1)
	if err != nil {
		return fmt.Errorf("storing challenge: %w", err)
	}
	return nil
}

// Peek reads the row for id without deleting it. An expired row reads as
// ErrNotFound and is left for Consume or the janitor.
func (p *Postgres) Peek(ctx context.Context, id string) (Challenge, error) {
	ch, err := p.scan(p.db.QueryRow(ctx,
		`SELECT message, did, expires_at, audience, scopes, jkt, client_key
		 FROM nonce_challenges WHERE nonce = $1`, id))
	if err != nil {
		return Challenge{}, fmt.Errorf("reading challenge: %w", err)
	}
	return ch, nil
}

// Consume deletes the row for id, only if it is bound to jkt, and returns it,
// in one atomic statement. As in the in-memory store, an expired row is still
// deleted but reported as ErrNotFound (delete-then-check), so the failure modes
// — unknown, already-used, expired, another key — are indistinguishable to the
// caller.
func (p *Postgres) Consume(ctx context.Context, id, jkt string) (Challenge, error) {
	ch, err := p.scan(p.db.QueryRow(ctx,
		`DELETE FROM nonce_challenges WHERE nonce = $1 AND jkt = $2
		 RETURNING message, did, expires_at, audience, scopes, jkt, client_key`, id, jkt))
	if err != nil {
		return Challenge{}, fmt.Errorf("consuming challenge: %w", err)
	}
	return ch, nil
}

// scan reads one challenge row. No row, or a row past its expiry, is
// ErrNotFound.
func (p *Postgres) scan(row pgx.Row) (Challenge, error) {
	var ch Challenge
	err := row.Scan(&ch.Message, &ch.DID, &ch.ExpiresAt, &ch.Audience, &ch.Scopes, &ch.JKT, &ch.Client)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Challenge{}, ErrNotFound
	case err != nil:
		return Challenge{}, err
	}
	if p.now().After(ch.ExpiresAt) {
		return Challenge{}, ErrNotFound
	}
	return ch, nil
}

// janitor periodically deletes expired rows. Consume already discards expired
// challenges, so this only reclaims rows for challenges that were never
// redeemed, keeping the table from accumulating abandoned sign-ins.
func (p *Postgres) janitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := p.db.Exec(ctx,
				`DELETE FROM nonce_challenges WHERE expires_at < $1`, p.now())
			if err != nil {
				p.log.Warn().Err(err).Msg("nonce janitor sweep failed")
				continue
			}
			if n := res.RowsAffected(); n > 0 {
				p.log.Debug().Int64("evicted", n).Msg("nonce janitor swept expired challenges")
			}
		}
	}
}
