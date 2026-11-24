package nonce

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testJKT is the DPoP key thumbprint test challenges are bound to.
const testJKT = "k"

func testChallenge(expiresAt time.Time) Challenge {
	return Challenge{
		Message:   "msg",
		DID:       "did:dimo:0x01",
		ExpiresAt: expiresAt,
		JKT:       testJKT,
	}
}

func TestPutConsume(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	ch := testChallenge(time.Now().Add(time.Minute))
	require.NoError(t, m.Put(ctx, "nonce-1", ch))

	got, err := m.Consume(ctx, "nonce-1", testJKT)
	require.NoError(t, err)
	assert.Equal(t, ch.DID, got.DID)
	assert.Equal(t, ch.Message, got.Message)
}

func TestConsume_SingleUse(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	require.NoError(t, m.Put(ctx, "n", testChallenge(time.Now().Add(time.Minute))))

	_, err := m.Consume(ctx, "n", testJKT)
	require.NoError(t, err)

	_, err = m.Consume(ctx, "n", testJKT)
	assert.ErrorIs(t, err, ErrNotFound, "a nonce must not be consumable twice")
}

func TestConsume_Unknown(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	_, err := m.Consume(ctx, "never-issued", testJKT)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestConsume_Expired(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	now := time.Now()
	require.NoError(t, m.Put(ctx, "n", testChallenge(now.Add(time.Minute))))

	// Advance the clock past expiry.
	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err := m.Consume(ctx, "n", testJKT)
	assert.ErrorIs(t, err, ErrNotFound, "an expired challenge must not be consumable")
}

// clientChallenge is a challenge asked for by the client with limit key c.
func clientChallenge(c string, expiresAt time.Time) Challenge {
	ch := testChallenge(expiresAt)
	ch.Client = c
	return ch
}

// live reports which of ids the store still holds.
func live(m *Memory, ids ...string) []string {
	var out []string
	for _, id := range ids {
		if _, err := m.Peek(context.Background(), id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// A client holds at most perClient challenges: the next one replaces its
// oldest, and other clients are untouched.
func TestPut_PerClientCapReplacesOldest(t *testing.T) {
	ctx := context.Background()
	m := newMemory(ctx, 1000, 3)
	future := time.Now().Add(time.Hour)
	require.NoError(t, m.Put(ctx, "other", clientChallenge("b", future)))
	for _, id := range []string{"a1", "a2", "a3", "a4", "a5"} {
		require.NoError(t, m.Put(ctx, id, clientChallenge("a", future)))
	}
	assert.Equal(t, []string{"a3", "a4", "a5"}, live(m, "a1", "a2", "a3", "a4", "a5"))
	assert.Equal(t, []string{"other"}, live(m, "other"))
	assert.Equal(t, 4, m.Len())

	// A consumed challenge frees its client's slot.
	_, err := m.Consume(ctx, "a4", testJKT)
	require.NoError(t, err)
	require.NoError(t, m.Put(ctx, "a6", clientChallenge("a", future)))
	assert.Equal(t, []string{"a3", "a5", "a6"}, live(m, "a3", "a5", "a6"))
}

// A full store never refuses: a new challenge replaces the oldest one of the
// client holding the most, so a flooder displaces its own challenges and never
// an honest client's.
func TestPut_FullStoreEvictsFromHeaviestClient(t *testing.T) {
	ctx := context.Background()
	m := newMemory(ctx, 6, 4)
	future := time.Now().Add(time.Hour)
	require.NoError(t, m.Put(ctx, "honest", clientChallenge("h", future)))
	require.NoError(t, m.Put(ctx, "b1", clientChallenge("b", future)))
	for _, id := range []string{"a1", "a2", "a3", "a4"} {
		require.NoError(t, m.Put(ctx, id, clientChallenge("a", future)))
	}
	require.Equal(t, 6, m.Len())

	// Full: a newcomer displaces a's oldest, not the honest client's.
	require.NoError(t, m.Put(ctx, "new", clientChallenge("n", future)))
	assert.Equal(t, 6, m.Len())
	assert.Equal(t, []string{"honest", "b1", "a2", "a3", "a4", "new"}, live(m, "honest", "b1", "a1", "a2", "a3", "a4", "new"))

	// The heaviest client's own new challenge displaces its own oldest.
	require.NoError(t, m.Put(ctx, "a5", clientChallenge("a", future)))
	assert.Equal(t, []string{"honest", "b1", "a3", "a4", "a5", "new"}, live(m, "honest", "b1", "a2", "a3", "a4", "a5", "new"))

	// Once every client holds one, any may go, but the store stays bounded.
	for i := range 20 {
		require.NoError(t, m.Put(ctx, fmt.Sprintf("x%d", i), clientChallenge(fmt.Sprintf("x%d", i), future)))
		require.Equal(t, 6, m.Len())
	}
}

// A full store drops expired challenges before it displaces a live one.
func TestPut_FullStoreDropsExpiredFirst(t *testing.T) {
	ctx := context.Background()
	m := newMemory(ctx, 3, 3)
	now := time.Now()
	m.now = func() time.Time { return now }
	require.NoError(t, m.Put(ctx, "old", clientChallenge("a", now.Add(time.Minute))))
	require.NoError(t, m.Put(ctx, "a2", clientChallenge("a", now.Add(time.Hour))))
	require.NoError(t, m.Put(ctx, "a3", clientChallenge("a", now.Add(time.Hour))))

	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	require.NoError(t, m.Put(ctx, "h", clientChallenge("h", now.Add(time.Hour))))
	assert.Equal(t, []string{"a2", "a3", "h"}, live(m, "old", "a2", "a3", "h"))
}

func TestJanitor_EvictsExpired(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	now := time.Now()
	require.NoError(t, m.Put(ctx, "n", testChallenge(now.Add(time.Minute))))
	require.NoError(t, m.Put(ctx, "later", testChallenge(now.Add(time.Hour))))

	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	// Drive the sweep directly rather than waiting for the ticker.
	m.mu.Lock()
	m.sweepLocked()
	m.mu.Unlock()
	assert.Equal(t, 1, m.Len())
	_, err := m.Consume(ctx, "n", testJKT)
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = m.Consume(ctx, "later", testJKT)
	assert.NoError(t, err)
}

func TestPeek_DoesNotConsume(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	ch := testChallenge(time.Now().Add(time.Minute))
	require.NoError(t, m.Put(ctx, "n", ch))

	for range 2 {
		got, err := m.Peek(ctx, "n")
		require.NoError(t, err)
		assert.Equal(t, ch.Message, got.Message)
	}
	_, err := m.Consume(ctx, "n", testJKT)
	require.NoError(t, err, "peeking must leave the challenge consumable")
	_, err = m.Peek(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "a consumed challenge must not be peekable")
}

func TestPeek_UnknownAndExpired(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	_, err := m.Peek(ctx, "never-issued")
	assert.ErrorIs(t, err, ErrNotFound)

	now := time.Now()
	require.NoError(t, m.Put(ctx, "n", testChallenge(now.Add(time.Minute))))
	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err = m.Peek(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "an expired challenge must not be peekable")
}

func TestConsume_WrongKeyLeavesChallenge(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	require.NoError(t, m.Put(ctx, "n", testChallenge(time.Now().Add(time.Minute))))

	_, err := m.Consume(ctx, "n", "another-key")
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = m.Consume(ctx, "n", testJKT)
	assert.NoError(t, err, "a consume naming another key must not spend the challenge")
}

func TestConsume_Concurrent(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	require.NoError(t, m.Put(ctx, "n", testChallenge(time.Now().Add(time.Minute))))

	const racers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := m.Consume(ctx, "n", testJKT); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else {
				assert.ErrorIs(t, err, ErrNotFound)
			}
		}()
	}
	close(start)
	wg.Wait()
	assert.Equal(t, 1, wins, "exactly one consumer must win the nonce")
}
