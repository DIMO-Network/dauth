package nonce

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

// floodResult is one run of simulateFlood.
type floodResult struct {
	honest, ok int
}

func (r floodResult) share() float64 { return float64(r.ok) / float64(r.honest) }

// simulateFlood is the challenge-flood simulation from the 2026-11-22 review
// (reviewer 5's scratch-5/flood, re-run by verifier V3), run against the real
// in-memory store:
//
//   - attackers client keys each POST /signin/challenge as fast as dauth's
//     per-client limit lets them (the shipped default: 5/s, burst 10; the
//     limiter is x/time/rate, which httpmw.KeyedLimiter wraps), from t=0;
//   - the store is sized as cmd/dauth sizes it, and challenges live 5 minutes
//     (CHALLENGE_TTL);
//   - from minute 6 to minute 10, honest clients, each from an address of its
//     own, start a sign-in at a random moment about every 50 ms, and retry a
//     refused challenge up to 3 attempts 1 s apart, as the SDK does;
//   - an honest sign-in succeeds when it gets a challenge and redeems it
//     redeemAfter later (the time to sign it and post /signin/token).
//
// Clocks are simulated in 10 ms steps.
func simulateFlood(t *testing.T, attackers, storeSize int, redeemAfter time.Duration) floodResult {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	start := time.Unix(1_800_000_000, 0)
	now := start
	m := NewMemory(t.Context(), storeSize)
	m.now = func() time.Time { return now }
	limiters := make([]*rate.Limiter, attackers)
	for i := range limiters {
		limiters[i] = rate.NewLimiter(5, 10)
	}
	const ttl = 5 * time.Minute
	put := func(client string) (string, error) {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		return id, m.Put(context.Background(), id, Challenge{ExpiresAt: now.Add(ttl), JKT: testJKT, Client: client})
	}

	type attempt struct {
		at     time.Time
		client string
		n      int
	}
	type redemption struct {
		at time.Time
		id string
	}
	var attempts []attempt
	var redemptions []redemption
	var res floodResult
	// The flood runs on past minute 10 until every honest sign-in started
	// before it has redeemed or given up.
	honestUntil := start.Add(10 * time.Minute)
	end := honestUntil.Add(3*time.Second + redeemAfter)
	for step := 10 * time.Millisecond; now.Before(end); now = now.Add(step) {
		for i, lim := range limiters {
			if lim.AllowN(now, 1) {
				_, _ = put(fmt.Sprintf("a%d", i))
			}
		}
		if now.After(start.Add(6*time.Minute)) && now.Before(honestUntil) && rng.Intn(5) == 0 {
			attempts = append(attempts, attempt{
				at:     now.Add(time.Duration(rng.Intn(10)) * time.Millisecond),
				client: fmt.Sprintf("h%d", res.honest),
				n:      1,
			})
			res.honest++
		}
		var waiting []attempt
		for _, a := range attempts {
			if a.at.After(now) {
				waiting = append(waiting, a)
				continue
			}
			id, err := put(a.client)
			switch {
			case err == nil:
				redemptions = append(redemptions, redemption{at: now.Add(redeemAfter), id: id})
			case a.n < 3:
				waiting = append(waiting, attempt{at: now.Add(time.Second), client: a.client, n: a.n + 1})
			}
		}
		attempts = waiting
		var pending []redemption
		for _, r := range redemptions {
			if r.at.After(now) {
				pending = append(pending, r)
				continue
			}
			if _, err := m.Consume(context.Background(), r.id, testJKT); err == nil {
				res.ok++
			}
		}
		redemptions = pending
	}
	return res
}

// R5-F1: a distributed challenge flood must not deny honest sign-ins. The
// review measured, with 3 attempts each, 98% honest success at 34 attacking
// client keys, 17% at 100 and 0% at 340 and 1,000. Honest sign-ins must keep
// succeeding against up to 1,000 attacking keys.
func TestMemoryFloodLeavesHonestSignInsWorking(t *testing.T) {
	if testing.Short() {
		t.Skip("simulates 10 minutes of a challenge flood")
	}
	const storeSize = 50_000 // cmd/dauth's maxOutstandingChallenges
	for _, attackers := range []int{34, 100, 340, 1000} {
		res := simulateFlood(t, attackers, storeSize, 10*time.Second)
		t.Logf("attacker keys=%4d (%4d challenges/s): honest sign-ins that got a challenge within 3 attempts and redeemed it 10s later: %d/%d (%.0f%%)",
			attackers, attackers*5, res.ok, res.honest, 100*res.share())
		assert.GreaterOrEqual(t, res.share(), 0.99, "attacker keys=%d", attackers)
	}
}
