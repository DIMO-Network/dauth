package nonce

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testChallenge(expiresAt time.Time) Challenge {
	return Challenge{
		Message:   "msg",
		Address:   common.HexToAddress("0x01"),
		ExpiresAt: expiresAt,
	}
}

func TestPutConsume(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	ch := testChallenge(time.Now().Add(time.Minute))
	require.NoError(t, m.Put(ctx, "nonce-1", ch))

	got, err := m.Consume(ctx, "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, ch.Address, got.Address)
	assert.Equal(t, ch.Message, got.Message)
}

func TestConsume_SingleUse(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	require.NoError(t, m.Put(ctx, "n", testChallenge(time.Now().Add(time.Minute))))

	_, err := m.Consume(ctx, "n")
	require.NoError(t, err)

	_, err = m.Consume(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound, "a nonce must not be consumable twice")
}

func TestConsume_Unknown(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	_, err := m.Consume(ctx, "never-issued")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestConsume_Expired(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(ctx, 1000)
	now := time.Now()
	require.NoError(t, m.Put(ctx, "n", testChallenge(now.Add(time.Minute))))

	// Advance the clock past expiry.
	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err := m.Consume(ctx, "n")
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
	_, err := m.Consume(ctx, "n")
	assert.ErrorIs(t, err, ErrNotFound)
}
