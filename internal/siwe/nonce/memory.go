package nonce

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

// shards splits the keyspace so expiry sweeps and lookups only ever contend on
// 1/shards of the table at once.
const shards = 64

// ErrFull is returned by Put when the store is at capacity even after evicting
// expired entries — back-pressure against a flood of challenge requests.
var ErrFull = fmt.Errorf("challenge store full")

type entry struct {
	ch        Challenge
	expiresAt time.Time
}

type shard struct {
	mu      sync.Mutex
	entries map[string]entry
}

// Memory is an in-memory, single-use, TTL-bounded challenge store. It is the
// default Store for a single-replica deployment. Running multiple replicas
// requires a shared store (e.g. Redis) so a nonce issued by one replica is
// consumable on another.
type Memory struct {
	shards     [shards]shard
	maxEntries int
	now        func() time.Time
}

// NewMemory returns a store bounded at maxEntries total and starts a background
// janitor that evicts expired entries until ctx is cancelled.
func NewMemory(ctx context.Context, maxEntries int) *Memory {
	m := &Memory{maxEntries: maxEntries, now: time.Now}
	for i := range m.shards {
		m.shards[i].entries = make(map[string]entry)
	}
	go m.janitor(ctx)
	return m
}

func (m *Memory) shard(id string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return &m.shards[h.Sum32()%shards]
}

// Put records ch under id, rejecting new entries once the per-shard capacity is
// reached (after first dropping any expired entries in that shard). The context
// is unused: the in-memory store does no cancellable I/O.
func (m *Memory) Put(_ context.Context, id string, ch Challenge) error {
	s := m.shard(id)
	s.mu.Lock()
	defer s.mu.Unlock()

	perShard := m.maxEntries / shards
	if perShard < 1 {
		perShard = 1
	}
	if len(s.entries) >= perShard {
		m.sweepLocked(s)
		if len(s.entries) >= perShard {
			return ErrFull
		}
	}
	s.entries[id] = entry{ch: ch, expiresAt: ch.ExpiresAt}
	return nil
}

// Consume atomically removes and returns the challenge for id.
func (m *Memory) Consume(_ context.Context, id string) (Challenge, error) {
	s := m.shard(id)
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[id]
	if !ok {
		return Challenge{}, ErrNotFound
	}
	delete(s.entries, id)
	if m.now().After(e.expiresAt) {
		return Challenge{}, ErrNotFound
	}
	return e.ch, nil
}

func (m *Memory) janitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := range m.shards {
				s := &m.shards[i]
				s.mu.Lock()
				m.sweepLocked(s)
				s.mu.Unlock()
			}
		}
	}
}

func (m *Memory) sweepLocked(s *shard) {
	now := m.now()
	for id, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, id)
		}
	}
}
