// Package server wires the sign-in (/siwe) HTTP surface. It follows din's
// conventions — standard net/http and explicit middleware composition. The
// sign-in handler is returned as a bare http.Handler with prefix-relative
// routes; the merged binary mounts it under /siwe and applies the panic
// recoverer once across both surfaces.
package server

import (
	"net/http"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/oidc"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// maxBodyBytes caps request bodies on the write endpoints. TLS, rate limiting,
// and any larger request-size policy are handled at the ingress; this is a cheap
// in-process belt against malformed giant bodies, mirroring the exchange surface.
const maxBodyBytes = 16 << 10 // 16 KiB

// SIWEConfig configures the sign-in surface.
type SIWEConfig struct {
	Handlers  *Handlers
	WellKnown *oidc.WellKnown
}

// NewSIWEHandler builds the sign-in surface as an http.Handler with routes
// relative to its mount point (/siwe). The two POST routes are body-capped; the
// read-only discovery and JWKS routes are exempt.
func NewSIWEHandler(cfg SIWEConfig) http.Handler {
	// Per-request guard applied only to the write endpoints.
	guard := httpmw.MaxBytes(maxBodyBytes)

	mux := http.NewServeMux()
	mux.Handle("POST /challenge", guard(cfg.Handlers.Challenge()))
	mux.Handle("POST /token", guard(cfg.Handlers.Token()))
	mux.Handle("GET /.well-known/openid-configuration", cfg.WellKnown.Discovery())
	mux.Handle("GET /keys", cfg.WellKnown.JWKS())
	mux.Handle("GET /.well-known/jwks.json", cfg.WellKnown.JWKS())

	// Interactive OpenAPI docs under dauth's own spec instance ("dauth"), so it
	// never collides with the permission surface's spec in this shared module.
	// Mounted under /siwe by the merged binary, so this serves /siwe/swagger/.
	mux.Handle("GET /swagger/", httpSwagger.Handler(httpSwagger.InstanceName("dauth")))
	return mux
}
