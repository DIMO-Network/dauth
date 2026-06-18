// Package httpmw holds the net/http middleware shared by both binaries: body
// caps, panic recovery, and a bounded per-remote rate limiter.
package httpmw

import (
	"hash/fnv"
	"math"
	"net"
	"net/http"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
)

// MaxBytes caps request body reads at limit bytes.
func MaxBytes(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Recover turns a handler panic into a 500 instead of crashing the process,
// logging the recovered value.
func Recover(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					log.Error().Interface("panic", v).Str("path", r.URL.Path).Msg("recovered from panic")
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// The rate limiter below is ported from din: one token bucket per remote key,
// sharded by key hash and bounded in total entries so churning source IPs can't
// grow memory without limit.

const limiterMaxKeys = 100_000
const limiterShards = 64

type remoteLimiter struct {
	shards [limiterShards]limiterShard
	rps    rate.Limit
	burst  int
}

type limiterShard struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newRemoteLimiter(rps float64, burst int) *remoteLimiter {
	l := &remoteLimiter{rps: rate.Limit(rps), burst: burst}
	for i := range l.shards {
		l.shards[i].limiters = map[string]*rate.Limiter{}
	}
	return l
}

func (l *remoteLimiter) shard(key string) *limiterShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &l.shards[h.Sum32()%limiterShards]
}

func (l *remoteLimiter) allow(key string) bool {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	lim, ok := s.limiters[key]
	if !ok {
		if len(s.limiters) >= limiterMaxKeys/limiterShards {
			s.evictLocked(l.burst)
		}
		lim = rate.NewLimiter(l.rps, l.burst)
		s.limiters[key] = lim
	}
	return lim.Allow()
}

// evictLocked drops idle entries from one shard. A bucket refilled to full
// burst is indistinguishable from a fresh one, so removing it changes nothing
// for that remote; if every bucket is hot, arbitrary entries go anyway —
// bounded memory beats perfect fairness.
func (s *limiterShard) evictLocked(burst int) {
	for key, lim := range s.limiters {
		if lim.Tokens() >= float64(burst) {
			delete(s.limiters, key)
		}
	}
	max := limiterMaxKeys / limiterShards
	if len(s.limiters) < max {
		return
	}
	dropped := 0
	for key := range s.limiters {
		delete(s.limiters, key)
		dropped++
		if dropped >= max/10 {
			break
		}
	}
}

// RateLimit enforces a per-remote-IP token bucket, answering 429 when the
// bucket is empty. rps <= 0 disables limiting.
func RateLimit(rps float64, burst int) func(http.Handler) http.Handler {
	if rps <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	if burst <= 0 {
		burst = int(math.Ceil(rps))
		if burst < 1 {
			burst = 1
		}
	}
	limiter := newRemoteLimiter(rps, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.allow(RemoteIP(r)) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RemoteIP returns the request's remote host address (without port), the key
// used for rate limiting and request logging.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
