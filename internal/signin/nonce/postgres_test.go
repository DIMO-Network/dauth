package nonce

import (
	"context"
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
		Message:   "canonical siwe message",
		DID:       "did:dimo:0xc0ffee254729296a45a3885639AC7E10F9d54979",
		ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond),
		Audience:  []string{"step-ca"},
	}
	require.NoError(t, p.Put(ctx, "nonce-1", ch))

	got, err := p.Consume(ctx, "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, ch.DID, got.DID)
	assert.Equal(t, ch.Message, got.Message)
	assert.True(t, ch.ExpiresAt.Equal(got.ExpiresAt))
	assert.Equal(t, ch.Audience, got.Audience)
}

func TestPostgres_SingleUse(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	require.NoError(t, p.Put(ctx, "n", Challenge{
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: time.Now().Add(time.Minute),
	}))

	_, err := p.Consume(ctx, "n")
	require.NoError(t, err)

	_, err = p.Consume(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "a nonce must not be consumable twice")
}

func TestPostgres_Unknown(t *testing.T) {
	p := newTestPostgres(t)
	_, err := p.Consume(context.Background(), "never-issued")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPostgres_Expired(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	now := time.Now()
	require.NoError(t, p.Put(ctx, "n", Challenge{
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: now.Add(time.Minute),
	}))

	// Advance the store's clock past expiry; the row is still deleted but
	// reported as missing.
	p.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err := p.Consume(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "an expired challenge must not be consumable")
}

// TestPostgres_ConcurrentConsume asserts the single-use guarantee holds under a
// race: many goroutines consuming the same nonce, exactly one wins.
func TestPostgres_ConcurrentConsume(t *testing.T) {
	ctx := context.Background()
	p := newTestPostgres(t)
	require.NoError(t, p.Put(ctx, "n", Challenge{
		Message: "m", DID: "did:dimo:0x01", ExpiresAt: time.Now().Add(time.Minute),
	}))

	const racers = 16
	results := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			_, err := p.Consume(ctx, "n")
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
