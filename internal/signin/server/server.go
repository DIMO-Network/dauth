// Package server wires the sign-in (/signin) HTTP surface: standard net/http
// and explicit middleware composition. The handler is returned as a bare
// http.Handler with prefix-relative routes; the binary mounts it under
// /signin and applies the panic recoverer once across both surfaces.
package server

import (
	"net/http"
	"net/netip"
	"slices"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/oidc"
)

// maxBodyBytes caps request bodies on the write endpoints: a cheap in-process
// belt against malformed giant bodies. TLS terminates at the ingress, which
// sets no rate limit; the per-client limit on the write endpoints is dauth's
// own (see rateLimit).
const maxBodyBytes = 16 << 10 // 16 KiB

// maxLimitedClients bounds how many client IPs the rate limiter tracks. A
// bucket is about 200 bytes with its map entry, so a full limiter is about
// 10 MB.
const maxLimitedClients = 50_000

// Config configures the sign-in surface.
type Config struct {
	Handlers  *Handlers
	WellKnown *oidc.WellKnown
	// CORSOrigins are the browser origins allowed to call /signin
	// (SIGNIN_CORS_ORIGINS). Empty means no CORS headers are sent.
	CORSOrigins []string
	// RateLimitPerSecond limits POST /challenge and POST /token, together, per
	// client IP, with a burst of twice the rate (SIGNIN_RATE_LIMIT_PER_SECOND).
	// Zero turns the limit off.
	RateLimitPerSecond int
	// TrustedProxies are the peers whose X-Forwarded-For names the client
	// (SIGNIN_TRUSTED_PROXIES); see httpmw.ClientIP.
	TrustedProxies []netip.Prefix
}

// NewHandler builds the sign-in surface as an http.Handler with routes
// relative to its mount point (/signin). The two POST routes are body-capped;
// the read-only discovery and JWKS routes are exempt.
func NewHandler(cfg Config) http.Handler {
	guard := httpmw.MaxBytes(maxBodyBytes)
	limit := rateLimit(cfg.RateLimitPerSecond)

	mux := http.NewServeMux()
	mux.Handle("POST /challenge", limit(guard(cfg.Handlers.Challenge())))
	mux.Handle("POST /token", limit(guard(cfg.Handlers.Token())))
	mux.Handle("GET /.well-known/openid-configuration", cfg.WellKnown.Discovery())
	mux.Handle("GET /keys", cfg.WellKnown.JWKS())
	mux.Handle("GET /.well-known/jwks.json", cfg.WellKnown.JWKS())
	return httpmw.ClientIP(cfg.TrustedProxies)(cors(cfg.CORSOrigins, mux))
}

// rateLimit limits the routes it wraps, together, per client IP (as
// httpmw.RemoteIP resolves it): perSecond requests a second with a burst of
// twice that. Over the limit is 429 rate_limited with Retry-After: 1, in the
// surface's usual error body. perSecond <= 0 turns it off.
func rateLimit(perSecond int) func(http.Handler) http.Handler {
	if perSecond <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	limiter := httpmw.NewKeyedLimiter(float64(perSecond), 2*perSecond, maxLimitedClients)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(httpmw.RemoteIP(r)) {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate_limited", "too many sign-in requests from this address, retry shortly")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// cors lets the listed origins call the sign-in surface from a browser. It
// answers an OPTIONS preflight from an allowed origin itself and adds the
// allow-origin header to the real responses; any other origin gets neither,
// and the browser blocks the call. Every response carries Vary: Origin, with
// or without an Origin header on the request, so a shared cache never serves
// one origin's answer to another. It is applied to /signin only, never to
// /exchange.
func cors(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if origin == "" || !slices.Contains(origins, origin) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, DPoP")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
