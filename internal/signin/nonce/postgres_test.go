package nonce

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPostgres connects to the database named by TEST_DATABASE_URL (a pgx
// connection URL, e.g. "postgres://user:pass@localhost:5432/dauth_test?sslmode=disable"),
// skipping the test when it is unset so CI without a database stays green. Each
// call starts from an empty table.
func newTestPostgres(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres challenge store tests")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	require.NoError(t, db.Ping(ctx))

	p, err := NewPostgres(ctx, db, zerolog.Nop())
	require.NoError(t, err)
	_, err = db.Exec(ctx, `TRUNCATE nonce_challenges`)
	require.NoError(t, err)
	return p
}

func TestPostgres_PutConsume(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)

	ch := Challenge{
		Message:   "canonical challenge text",
		DID:       "did:dimo:0xc0ffee254729296a45a3885639AC7E10F9d54979",
		ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond),
		Audience:  []string{"step-ca"},
		Scopes:    []string{"read", "write"},
		JKT:       "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
	}
	require.NoError(t, p.Put(ctx, "nonce-1", ch))

	got, err := p.Consume(ctx, "nonce-1", ch.JKT)
	require.NoError(t, err)
	assert.Equal(t, ch.DID, got.DID)
	assert.Equal(t, ch.Message, got.Message)
	assert.True(t, ch.ExpiresAt.Equal(got.ExpiresAt))
	assert.Equal(t, ch.Audience, got.Audience)
	assert.Equal(t, ch.Scopes, got.Scopes)
	assert.Equal(t, ch.JKT, got.JKT)
}

func TestPostgres_SingleUse(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	require.NoError(t, p.Put(ctx, "n", Challenge{Scopes: []string{"read"}, JKT: "k",
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: time.Now().Add(time.Minute),
	}))

	_, err := p.Consume(ctx, "n", "k")
	require.NoError(t, err)

	_, err = p.Consume(ctx, "n", "k")
	assert.ErrorIs(t, err, ErrNotFound, "a nonce must not be consumable twice")
}

func TestPostgres_Unknown(t *testing.T) {
	p := newTestPostgres(t)
	_, err := p.Consume(context.Background(), "never-issued", "k")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPostgres_Expired(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	now := time.Now()
	require.NoError(t, p.Put(ctx, "n", Challenge{Scopes: []string{"read"}, JKT: "k",
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: now.Add(time.Minute),
	}))

	// Advance the store's clock past expiry; the row is still deleted but
	// reported as missing.
	p.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err := p.Consume(ctx, "n", "k")
	assert.ErrorIs(t, err, ErrNotFound, "an expired challenge must not be consumable")
}

// TestPostgres_ConcurrentConsume asserts the single-use guarantee holds under a
// race: many goroutines consuming the same nonce, exactly one wins.
func TestPostgres_ConcurrentConsume(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	require.NoError(t, p.Put(ctx, "n", Challenge{Scopes: []string{"read"}, JKT: "k",
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: time.Now().Add(time.Minute),
	}))

	const racers = 16
	results := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			_, err := p.Consume(ctx, "n", "k")
			results <- err
		}()
	}
	close(start)

	var wins int
	for i := 0; i < racers; i++ {
		if err := <-results; err == nil {
			wins++
		} else {
			assert.ErrorIs(t, err, ErrNotFound)
		}
	}
	assert.Equal(t, 1, wins, "exactly one consumer must win the nonce")
}

func TestPostgres_Peek(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	now := time.Now()
	ch := Challenge{Scopes: []string{"read"}, JKT: "k", Audience: []string{"dimo"},
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: now.Add(time.Minute).UTC().Truncate(time.Microsecond),
	}
	require.NoError(t, p.Put(ctx, "n", ch))

	for range 2 {
		got, err := p.Peek(ctx, "n")
		require.NoError(t, err)
		assert.Equal(t, ch.Message, got.Message)
		assert.Equal(t, ch.Audience, got.Audience)
		assert.Equal(t, ch.JKT, got.JKT)
	}
	_, err := p.Peek(ctx, "never-issued")
	assert.ErrorIs(t, err, ErrNotFound)

	p.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err = p.Peek(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "an expired challenge must not be peekable")
	p.now = time.Now

	_, err = p.Consume(ctx, "n", "k")
	require.NoError(t, err, "peeking must leave the challenge consumable")
	_, err = p.Peek(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "a consumed challenge must not be peekable")
}

func TestPostgres_WrongKeyLeavesChallenge(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	require.NoError(t, p.Put(ctx, "n", Challenge{Scopes: []string{"read"}, JKT: "k",
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: time.Now().Add(time.Minute),
	}))

	_, err := p.Consume(ctx, "n", "another-key")
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = p.Consume(ctx, "n", "k")
	assert.NoError(t, err, "a consume naming another key must not spend the challenge")
}

// Replicas starting together all bootstrap the schema at once. Each run is in
// a fresh, randomly named schema so the CREATE TABLE IF NOT EXISTS race is
// real, and every concurrent NewPostgres must succeed.
func TestPostgres_ConcurrentSchemaBootstrap(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres challenge store tests")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	admin, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(admin.Close)

	for round := range 5 {
		name := fmt.Sprintf("bootstrap_%d_%d", time.Now().UnixNano(), round)
		_, err := admin.Exec(ctx, `CREATE SCHEMA `+name)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := admin.Exec(context.Background(), `DROP SCHEMA `+name+` CASCADE`)
			assert.NoError(t, err)
		})

		cfg, err := pgxpool.ParseConfig(dsn)
		require.NoError(t, err)
		cfg.ConnConfig.RuntimeParams["search_path"] = name
		cfg.MaxConns = 16
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)

		const replicas = 8
		errs := make(chan error, replicas)
		start := make(chan struct{})
		for range replicas {
			go func() {
				<-start
				_, err := NewPostgres(ctx, pool, zerolog.Nop())
				errs <- err
			}()
		}
		close(start)
		for range replicas {
			assert.NoError(t, <-errs, "round %d", round)
		}
	}
}

// R5-F1: the Postgres store keeps the same per-client budget as the
// in-memory one. A client past MaxPerClient loses its oldest challenge, and
// other clients are untouched, so a flood cannot grow the table past
// MaxPerClient rows per address.
func TestPostgres_PerClientCapReplacesOldest(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	now := time.Now()
	put := func(n, client string, at time.Time) {
		t.Helper()
		require.NoError(t, p.Put(ctx, n, Challenge{Scopes: []string{"read"}, JKT: "k",
			Message: "m", DID: "did:dimo:0x01", ExpiresAt: at, Client: client,
		}))
	}
	put("other", "198.51.100.7", now.Add(time.Minute))
	for i := range MaxPerClient + 2 {
		put(fmt.Sprintf("a%02d", i), "203.0.113.1", now.Add(time.Minute+time.Duration(i)*time.Millisecond))
	}

	for i := range MaxPerClient + 2 {
		_, err := p.Peek(ctx, fmt.Sprintf("a%02d", i))
		if i < 2 {
			assert.ErrorIs(t, err, ErrNotFound, "a%02d: the client's oldest challenges are displaced", i)
		} else {
			assert.NoError(t, err, "a%02d", i)
		}
	}
	got, err := p.Peek(ctx, "other")
	require.NoError(t, err, "another client's challenge is untouched")
	assert.Equal(t, "198.51.100.7", got.Client)

	var rows int
	require.NoError(t, p.db.QueryRow(ctx, `SELECT count(*) FROM nonce_challenges WHERE client_key = $1`, "203.0.113.1").Scan(&rows))
	assert.Equal(t, MaxPerClient, rows)
}

// A table made before the per-client budget gains its column at startup and
// keeps its rows.
func TestPostgres_UpgradesTableWithoutClientColumn(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres challenge store tests")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(admin.Close)

	name := fmt.Sprintf("upgrade_%d", time.Now().UnixNano())
	_, err = admin.Exec(ctx, `CREATE SCHEMA `+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec(context.Background(), `DROP SCHEMA `+name+` CASCADE`)
		assert.NoError(t, err)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `CREATE TABLE nonce_challenges (
		nonce TEXT PRIMARY KEY, message TEXT NOT NULL, did TEXT NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL, audience TEXT[], scopes TEXT[] NOT NULL, jkt TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO nonce_challenges (nonce, message, did, expires_at, scopes, jkt)
		VALUES ('before', 'm', 'did:dimo:0x01', now() + interval '1 minute', '{read}', 'k')`)
	require.NoError(t, err)

	p, err := NewPostgres(ctx, pool, zerolog.Nop())
	require.NoError(t, err)
	_, err = p.Peek(ctx, "before")
	require.NoError(t, err, "an outstanding challenge survives the upgrade")
	require.NoError(t, p.Put(ctx, "after", Challenge{Scopes: []string{"read"}, JKT: "k",
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: time.Now().Add(time.Minute), Client: "203.0.113.1",
	}))
	got, err := p.Peek(ctx, "after")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.1", got.Client)
}

// A replica starting while others serve must not lock the table: once the
// schema is current, bootstrap takes no lock that waits for readers (ALTER
// TABLE would take ACCESS EXCLUSIVE, queued behind every open transaction
// that has touched the table, with every later query queued behind it).
func TestPostgres_StartupDoesNotWaitForReaders(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres challenge store tests")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(admin.Close)

	name := fmt.Sprintf("startup_%d", time.Now().UnixNano())
	_, err = admin.Exec(ctx, `CREATE SCHEMA `+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec(context.Background(), `DROP SCHEMA `+name+` CASCADE`)
		assert.NoError(t, err)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = NewPostgres(ctx, pool, zerolog.Nop())
	require.NoError(t, err)

	// Another replica's request is mid-transaction on the table.
	reader, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Rollback(context.Background()) })
	_, err = reader.Exec(ctx, `SELECT count(*) FROM nonce_challenges`)
	require.NoError(t, err)

	startCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	_, err = NewPostgres(startCtx, pool, zerolog.Nop())
	assert.NoError(t, err, "bootstrap must not wait for the open reader")
}
