// Package server wires the sign-in (/signin) HTTP surface: standard net/http
// and explicit middleware composition. The handler is returned as a bare
// http.Handler with prefix-relative routes; the binary mounts it under
// /signin and applies the panic recoverer once across both surfaces.
package server

import (
	"net/http"

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
	return mux
}
