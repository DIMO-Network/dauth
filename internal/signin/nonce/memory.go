package nonce

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// entry is one stored challenge, linked into the store's list of every entry
// and into its client's list, both oldest first.
type entry struct {
	id     string
	ch     Challenge
	client *client
	all    *list.Element // in Memory.order
	own    *list.Element // in client.entries
}

// client is the challenges one rate-limit key holds, oldest first.
type client struct {
	key     string
	entries list.List
	bucket  *list.Element // in Memory.byCount[entries.Len()]
}

// Memory is an in-memory, single-use, TTL-bounded challenge store. It is the
// default Store for a single-replica deployment. Running multiple replicas
// requires the shared Postgres store, so a nonce issued by one replica is
// consumable on another.
//
// POST /signin/challenge is unauthenticated, so the store budgets by client
// (Challenge.Client) rather than by arrival. A client holds at most
// MaxPerClient challenges: a new one replaces that client's oldest. When the
// store is full, a new challenge replaces the oldest one of whichever client
// holds the most. Put never refuses, and a flood only ever displaces the
// flooders' own challenges: an honest client holding one or two outstanding
// challenges is never the heaviest while any flooding client holds more. The
// 2026-11-22 review's simulation (flood_test.go) runs this against up to
// 1,000 flooding clients.
type Memory struct {
	mu      sync.Mutex
	entries map[string]*entry
	order   list.List // every *entry, oldest first
	clients map[string]*client
	// byCount[n] lists the clients holding n challenges (1 <= n <= perClient);
	// heaviest is the highest n with a client in it.
	byCount    []list.List
	heaviest   int
	maxEntries int
	perClient  int
	now        func() time.Time
}

// NewMemory returns a store bounded at maxEntries challenges in all and
// MaxPerClient per client, and starts a background janitor that evicts expired
// entries until ctx is cancelled.
func NewMemory(ctx context.Context, maxEntries int) *Memory {
	return newMemory(ctx, maxEntries, MaxPerClient)
}

func newMemory(ctx context.Context, maxEntries, perClient int) *Memory {
	maxEntries, perClient = max(1, maxEntries), max(1, perClient)
	m := &Memory{
		entries:    make(map[string]*entry),
		clients:    make(map[string]*client),
		byCount:    make([]list.List, perClient+1),
		maxEntries: maxEntries,
		perClient:  perClient,
		now:        time.Now,
	}
	go m.janitor(ctx)
	return m
}

// Put records ch under id. A client already holding perClient challenges
// loses its oldest. A full store first drops expired entries from its oldest
// end, then, if still full, the oldest challenge of the client holding the
// most. The context is unused: the in-memory store does no cancellable I/O.
func (m *Memory) Put(_ context.Context, id string, ch Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if old, ok := m.entries[id]; ok {
		m.removeLocked(old)
	}
	if c, ok := m.clients[ch.Client]; ok && c.entries.Len() >= m.perClient {
		m.removeLocked(c.entries.Front().Value.(*entry))
	}
	if len(m.entries) >= m.maxEntries {
		m.expireOldestLocked()
	}
	if len(m.entries) >= m.maxEntries {
		heavy := m.byCount[m.heaviest].Front().Value.(*client)
		m.removeLocked(heavy.entries.Front().Value.(*entry))
	}

	c, ok := m.clients[ch.Client]
	if !ok {
		c = &client{key: ch.Client}
		m.clients[ch.Client] = c
	}
	e := &entry{id: id, ch: ch, client: c}
	e.all = m.order.PushBack(e)
	m.unbucketLocked(c)
	e.own = c.entries.PushBack(e)
	m.bucketLocked(c)
	m.entries[id] = e
	return nil
}

// Peek returns the challenge for id without removing it.
func (m *Memory) Peek(_ context.Context, id string) (Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[id]
	if !ok || m.now().After(e.ch.ExpiresAt) {
		return Challenge{}, ErrNotFound
	}
	return e.ch, nil
}

// Consume atomically removes and returns the challenge for id when it is bound
// to jkt. The key is checked and the entry deleted under the store's lock, so
// of concurrent callers at most one gets it; a challenge for another key is
// left in place.
func (m *Memory) Consume(_ context.Context, id, jkt string) (Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[id]
	if !ok {
		return Challenge{}, ErrNotFound
	}
	if m.now().After(e.ch.ExpiresAt) {
		m.removeLocked(e)
		return Challenge{}, ErrNotFound
	}
	if e.ch.JKT != jkt {
		return Challenge{}, ErrNotFound
	}
	m.removeLocked(e)
	return e.ch, nil
}

// Len is how many challenges the store holds, expired ones included until
// they are swept.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// removeLocked unlinks e from the store and from its client, dropping the
// client once it holds nothing.
func (m *Memory) removeLocked(e *entry) {
	delete(m.entries, e.id)
	m.order.Remove(e.all)
	c := e.client
	m.unbucketLocked(c)
	c.entries.Remove(e.own)
	if c.entries.Len() == 0 {
		delete(m.clients, c.key)
		return
	}
	m.bucketLocked(c)
}

// unbucketLocked takes c out of the count bucket it is in, if any.
func (m *Memory) unbucketLocked(c *client) {
	if c.bucket == nil {
		return
	}
	m.byCount[c.entries.Len()].Remove(c.bucket)
	c.bucket = nil
	for m.heaviest > 0 && m.byCount[m.heaviest].Len() == 0 {
		m.heaviest--
	}
}

// bucketLocked files c under the number of challenges it now holds.
func (m *Memory) bucketLocked(c *client) {
	n := c.entries.Len()
	c.bucket = m.byCount[n].PushBack(c)
	m.heaviest = max(m.heaviest, n)
}

// expireOldestLocked drops expired entries from the oldest end of the store.
// Challenges share one TTL, so the oldest are the first to expire, and this
// stops at the first live one; the janitor sweeps the whole store.
func (m *Memory) expireOldestLocked() {
	now := m.now()
	for front := m.order.Front(); front != nil; front = m.order.Front() {
		e := front.Value.(*entry)
		if !now.After(e.ch.ExpiresAt) {
			return
		}
		m.removeLocked(e)
	}
}

// sweepLocked drops every expired entry.
func (m *Memory) sweepLocked() {
	now := m.now()
	for el := m.order.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*entry); now.After(e.ch.ExpiresAt) {
			m.removeLocked(e)
		}
		el = next
	}
}

func (m *Memory) janitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			m.sweepLocked()
			m.mu.Unlock()
		}
	}
}
