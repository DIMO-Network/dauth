package nonce

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

//go:embed schema.sql
var schema string

// Postgres is a Store backed by a single nonce_challenges table. Unlike the
// in-memory store it is shared across replicas, so a challenge issued by one
// dauth pod is consumable on any other — which is what lets dauth run more than
// one replica. Single-use consumption is a DELETE ... RETURNING, atomic even
// under concurrent /auth/token calls racing on the same nonce: exactly one
// caller gets the row, every other gets ErrNotFound.
//
// There is no hard capacity cap here (the in-memory store's ErrFull guards a
// process's heap). A flood of unredeemed challenges is bounded instead by the
// HTTP rate limiter in front of /auth/challenge and by the janitor sweeping
// expired rows; each row is tiny and short-lived.
type Postgres struct {
	db  *pgxpool.Pool
	now func() time.Time
	log zerolog.Logger
}

// NewPostgres ensures the schema exists on db and starts a background janitor
// that evicts expired challenges until ctx is cancelled. The caller owns db's
// lifecycle (open and Close).
func NewPostgres(ctx context.Context, db *pgxpool.Pool, log zerolog.Logger) (*Postgres, error) {
	if _, err := db.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("ensuring nonce schema: %w", err)
	}
	p := &Postgres{db: db, now: time.Now, log: log}
	go p.janitor(ctx)
	return p, nil
}

// Put inserts ch under id. A duplicate nonce (astronomically unlikely for 32
// random bytes) surfaces as an error and the handler reports the challenge
// store unavailable.
func (p *Postgres) Put(ctx context.Context, id string, ch Challenge) error {
	_, err := p.db.Exec(ctx,
		`INSERT INTO nonce_challenges (nonce, message, address, expires_at, audience)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, ch.Message, ch.Address.Bytes(), ch.ExpiresAt, ch.Audience)
	if err != nil {
		return fmt.Errorf("storing challenge: %w", err)
	}
	return nil
}

// Consume deletes the row for id and returns it, in one atomic statement. As in
// the in-memory store, an expired row is still deleted but reported as
// ErrNotFound (delete-then-check), so the three failure modes — unknown,
// already-used, expired — are indistinguishable to the caller.
func (p *Postgres) Consume(ctx context.Context, id string) (Challenge, error) {
	var (
		msg     string
		addr    []byte
		expires time.Time
		aud     []string
	)
	err := p.db.QueryRow(ctx,
		`DELETE FROM nonce_challenges WHERE nonce = $1
		 RETURNING message, address, expires_at, audience`, id).
		Scan(&msg, &addr, &expires, &aud)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Challenge{}, ErrNotFound
	case err != nil:
		return Challenge{}, fmt.Errorf("consuming challenge: %w", err)
	}
	if p.now().After(expires) {
		return Challenge{}, ErrNotFound
	}
	return Challenge{
		Message:   msg,
		Address:   common.BytesToAddress(addr),
		ExpiresAt: expires,
		Audience:  aud,
	}, nil
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
