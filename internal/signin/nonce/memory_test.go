package nonce

import (
	"context"
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

func TestPut_CapEnforced(t *testing.T) {
	ctx := context.Background()
	// maxEntries == shards => one entry per shard. With more distinct keys than
	// shards, the pigeonhole guarantees at least one collision and an ErrFull.
	m := NewMemory(ctx, shards)
	future := time.Now().Add(time.Hour)
	var full, ok int
	for i := 0; i < shards*4; i++ {
		err := m.Put(ctx, string(rune('a'+i%26))+time.Duration(i).String(), testChallenge(future))
		if err == ErrFull {
			full++
		} else {
			require.NoError(t, err)
			ok++
		}
	}
	assert.Positive(t, ok)
	assert.Positive(t, full, "the store must reject entries past its capacity")
}

func TestJanitor_EvictsExpired(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	now := time.Now()
	require.NoError(t, m.Put(ctx, "n", testChallenge(now.Add(time.Minute))))

	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	// Drive the sweep directly rather than waiting for the ticker.
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		m.sweepLocked(s)
		s.mu.Unlock()
	}
	_, err := m.Consume(ctx, "n", testJKT)
	assert.ErrorIs(t, err, ErrNotFound)
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
