// Package httpmw holds the net/http middleware dauth's surfaces share: body
// caps, panic recovery, client IP resolution and a per-key rate limiter.
package httpmw

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/rs/zerolog"
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

// clientIPKey is the context key ClientIP stores the resolved address under.
type clientIPKey struct{}

// ClientIP resolves each request's client address once and stores it for
// RemoteIP, so logging and rate limiting agree on who the client is.
//
// The trust model: the TCP peer is the client, unless the peer is inside
// trusted (the ingress controller, say). Only then is X-Forwarded-For read,
// right to left, and the first address that is not itself trusted is the
// client: entries to the left of it were written by parties dauth has no
// reason to believe. An entry may be a bare address or address:port
// ([v6]:port); one that is neither, or that carries an IPv6 zone (%...),
// stops the walk and the peer is used, so a client can never choose its own
// key. With trusted empty, X-Forwarded-For is ignored altogether.
func ClientIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trusted)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip)))
		})
	}
}

// RemoteIP returns the client address ClientIP resolved for r, or the TCP
// peer's address (without port) when ClientIP did not run. It keys request
// logging and the /signin rate limit.
func RemoteIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok {
		return ip
	}
	return peerIP(r)
}

// peerIP is the TCP peer's address, unmapped and without any IPv6 zone.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return host
}

// parseHop reads one X-Forwarded-For entry: an address, or address:port as
// some proxies write it. A zoned IPv6 address is refused: a zone only means
// something on the host that wrote it.
func parseHop(hop string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(hop)
	if err != nil {
		ap, perr := netip.ParseAddrPort(hop)
		if perr != nil {
			return netip.Addr{}, false
		}
		a = ap.Addr()
	}
	if a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// LimitKey is the rate-limit key for a client address: the address itself
// for IPv4, and its /64 for IPv6, since one subscriber is typically given a
// whole /64 and could otherwise rotate through it for fresh buckets. Anything
// that is not an address is its own key.
func LimitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if a = a.Unmap().WithZone(""); a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

func resolveClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := peerIP(r)
	if len(trusted) == 0 {
		return peer
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !inAny(trusted, addr) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		a, ok := parseHop(hop)
		if !ok {
			return peer
		}
		if !inAny(trusted, a) {
			return a.String()
		}
	}
	return peer
}

func inAny(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
