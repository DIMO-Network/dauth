// Package server wires the sign-in (/signin) HTTP surface: standard net/http
// and explicit middleware composition. The handler is returned as a bare
// http.Handler with prefix-relative routes; the binary mounts it under
// /signin and applies the panic recoverer once across both surfaces.
package server

import (
	"net/http"
	"slices"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/oidc"
)

// maxBodyBytes caps request bodies on the write endpoints. TLS, rate limiting,
// and any larger request-size policy are handled at the ingress; this is a cheap
// in-process belt against malformed giant bodies.
const maxBodyBytes = 16 << 10 // 16 KiB

// Config configures the sign-in surface.
type Config struct {
	Handlers  *Handlers
	WellKnown *oidc.WellKnown
	// CORSOrigins are the browser origins allowed to call /signin
	// (SIGNIN_CORS_ORIGINS). Empty means no CORS headers are sent.
	CORSOrigins []string
}

// NewHandler builds the sign-in surface as an http.Handler with routes
// relative to its mount point (/signin). The two POST routes are body-capped;
// the read-only discovery and JWKS routes are exempt.
func NewHandler(cfg Config) http.Handler {
	guard := httpmw.MaxBytes(maxBodyBytes)

	mux := http.NewServeMux()
	mux.Handle("POST /challenge", guard(cfg.Handlers.Challenge()))
	mux.Handle("POST /token", guard(cfg.Handlers.Token()))
	mux.Handle("GET /.well-known/openid-configuration", cfg.WellKnown.Discovery())
	mux.Handle("GET /keys", cfg.WellKnown.JWKS())
	mux.Handle("GET /.well-known/jwks.json", cfg.WellKnown.JWKS())
	return cors(cfg.CORSOrigins, mux)
}

// cors lets the listed origins call the sign-in surface from a browser. It
// answers an OPTIONS preflight from an allowed origin itself and adds the
// allow-origin header to the real responses; any other origin gets neither,
// and the browser blocks the call. It is applied to /signin only, never to
// /exchange.
func cors(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		if !slices.Contains(origins, origin) {
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
