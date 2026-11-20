package httpmw

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestKeyedLimiterPerKey(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := NewKeyedLimiter(5, 10, 1000)
	l.now = func() time.Time { return now }

	for i := range 10 {
		assert.True(t, l.Allow("198.51.100.1"), "burst request %d", i)
	}
	assert.False(t, l.Allow("198.51.100.1"), "the 11th request in the same instant is over the burst")
	assert.True(t, l.Allow("198.51.100.2"), "another key has its own bucket")

	now = now.Add(time.Second)
	for i := range 5 {
		assert.True(t, l.Allow("198.51.100.1"), "refilled request %d", i)
	}
	assert.False(t, l.Allow("198.51.100.1"), "one second refills 5, no more")
}

func TestKeyedLimiterStaysBounded(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	const maxKeys = 640
	l := NewKeyedLimiter(5, 10, maxKeys)
	l.now = func() time.Time { return now }

	// Every bucket stays hot (each key spends its whole burst), so eviction
	// has to drop in-use buckets too.
	for i := range 20 * maxKeys {
		key := fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		for range 10 {
			l.Allow(key)
		}
		if n := l.Len(); n > maxKeys {
			t.Fatalf("after %d keys the limiter tracks %d, over its bound of %d", i+1, n, maxKeys)
		}
	}
	assert.LessOrEqual(t, l.Len(), maxKeys)
	assert.Positive(t, l.Len())
}

func trusted(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func clientIPOf(t *testing.T, peer string, xff []string, proxies []netip.Prefix) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/challenge", nil)
	r.RemoteAddr = peer
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	var got string
	ClientIP(proxies)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = RemoteIP(r)
	})).ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func TestClientIPTrustModel(t *testing.T) {
	ingress := trusted(t, "10.0.0.0/8")
	for _, tc := range []struct {
		name    string
		peer    string
		xff     []string
		proxies []netip.Prefix
		want    string
	}{
		{"no trusted proxies: X-Forwarded-For is ignored", "10.1.2.3:5555", []string{"203.0.113.9"}, nil, "10.1.2.3"},
		{"untrusted peer cannot claim an address", "198.51.100.7:5555", []string{"203.0.113.9"}, ingress, "198.51.100.7"},
		{"trusted peer: its X-Forwarded-For names the client", "10.1.2.3:5555", []string{"203.0.113.9"}, ingress, "203.0.113.9"},
		{"rightmost untrusted wins over a spoofed left entry", "10.1.2.3:5555", []string{"1.1.1.1, 203.0.113.9"}, ingress, "203.0.113.9"},
		{"trusted hops are skipped", "10.1.2.3:5555", []string{"203.0.113.9, 10.9.9.9"}, ingress, "203.0.113.9"},
		{"several header lines read as one list", "10.1.2.3:5555", []string{"1.1.1.1", "203.0.113.9"}, ingress, "203.0.113.9"},
		{"all hops trusted: the peer", "10.1.2.3:5555", []string{"10.4.4.4"}, ingress, "10.1.2.3"},
		{"no header: the peer", "10.1.2.3:5555", nil, ingress, "10.1.2.3"},
		{"garbage stops the walk: the peer", "10.1.2.3:5555", []string{"203.0.113.9, not-an-ip"}, ingress, "10.1.2.3"},
		{"IPv4-mapped IPv6 is unmapped", "[::ffff:10.1.2.3]:5555", []string{"::ffff:203.0.113.9"}, ingress, "203.0.113.9"},
		{"IPv6 client", "10.1.2.3:5555", []string{"2001:db8::1"}, ingress, "2001:db8::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clientIPOf(t, tc.peer, tc.xff, tc.proxies))
		})
	}
}

func TestRemoteIPWithoutClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.4:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	assert.Equal(t, "192.0.2.4", RemoteIP(r), "without ClientIP, RemoteIP is the TCP peer")
}
