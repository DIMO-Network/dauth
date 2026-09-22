package dpop

import (
	"sync"
	"time"
)

// replayCache remembers accepted proof ids until they can no longer be
// presented, so a captured proof cannot be replayed within its window. It is
// per process; a resource server running several replicas accepts a replay on
// another replica, which the short proof lifetime bounds.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// sweepAt is when expired entries are next dropped.
	sweepAt time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: map[string]time.Time{}}
}

// add records jti until expiry and reports false if it was already present.
func (c *replayCache) add(jti string, expiry, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !now.Before(c.sweepAt) {
		for id, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, id)
			}
		}
		c.sweepAt = now.Add(time.Minute)
	}
	if exp, ok := c.seen[jti]; ok && now.Before(exp) {
		return false
	}
	c.seen[jti] = expiry
	return true
}
