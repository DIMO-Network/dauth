package httpmw

import (
	"hash/fnv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterShards splits the limiter's keyspace so requests from different
// clients rarely contend on one lock.
const limiterShards = 64

// KeyedLimiter is a token bucket per key (a client IP), bounded in how many
// keys it tracks so a flood of source addresses cannot grow memory without
// limit. When a shard is full, buckets that have refilled to their burst go
// first: such a bucket is indistinguishable from a new one, so dropping it
// changes nothing for that client. If every bucket in the shard is in use, a
// tenth of them go anyway, and those clients start again from a full burst:
// bounded memory wins over perfect fairness.
type KeyedLimiter struct {
	shards      [limiterShards]limiterShard
	limit       rate.Limit
	burst       int
	maxPerShard int
	now         func() time.Time
}

type limiterShard struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewKeyedLimiter allows perSecond events per key with the given burst, and
// tracks at most maxKeys keys (rounded up to a multiple of the shard count).
func NewKeyedLimiter(perSecond float64, burst, maxKeys int) *KeyedLimiter {
	l := &KeyedLimiter{
		limit:       rate.Limit(perSecond),
		burst:       burst,
		maxPerShard: max(1, (maxKeys+limiterShards-1)/limiterShards),
		now:         time.Now,
	}
	for i := range l.shards {
		l.shards[i].limiters = map[string]*rate.Limiter{}
	}
	return l
}

// Allow reports whether key may have one more event now, and spends it.
func (l *KeyedLimiter) Allow(key string) bool {
	now := l.now()
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	lim, ok := s.limiters[key]
	if !ok {
		if len(s.limiters) >= l.maxPerShard {
			l.evictLocked(s, now)
		}
		lim = rate.NewLimiter(l.limit, l.burst)
		s.limiters[key] = lim
	}
	return lim.AllowN(now, 1)
}

// Len is how many keys the limiter tracks.
func (l *KeyedLimiter) Len() int {
	n := 0
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		n += len(s.limiters)
		s.mu.Unlock()
	}
	return n
}

func (l *KeyedLimiter) shard(key string) *limiterShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &l.shards[h.Sum32()%limiterShards]
}

func (l *KeyedLimiter) evictLocked(s *limiterShard, now time.Time) {
	for key, lim := range s.limiters {
		if lim.TokensAt(now) >= float64(l.burst) {
			delete(s.limiters, key)
		}
	}
	if len(s.limiters) < l.maxPerShard {
		return
	}
	drop := max(1, l.maxPerShard/10)
	for key := range s.limiters {
		delete(s.limiters, key)
		if drop--; drop == 0 {
			break
		}
	}
}
