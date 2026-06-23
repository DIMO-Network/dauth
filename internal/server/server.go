// Package server wires the sign-in (/siwe) HTTP surface and the ops server
// (probes and Prometheus metrics). It follows din's conventions — standard
// net/http and explicit middleware composition. The sign-in handler is returned
// as a bare http.Handler with prefix-relative routes; the merged binary mounts
// it under /siwe and applies the panic recoverer once across both surfaces.
package server

import (
	"net/http"
	nethttppprof "net/http/pprof"
	"time"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

const (
	DefaultOpsAddr      = ":8081"
	DefaultTimeout      = 10 * time.Second
	DefaultMaxBodyBytes = 16 << 10 // 16 KiB
)

// SIWEConfig configures the sign-in surface.
type SIWEConfig struct {
	Handlers       *Handlers
	WellKnown      *oidc.WellKnown
	MaxBodyBytes   int64
	RateLimitRPS   float64
	RateLimitBurst int
}

// NewSIWEHandler builds the sign-in surface as an http.Handler with routes
// relative to its mount point (/siwe). The two POST routes are rate-limited and
// body-capped; the read-only discovery and JWKS routes are exempt so token
// validators polling the JWKS are never throttled.
func NewSIWEHandler(cfg SIWEConfig) http.Handler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}

	// Per-request guards applied only to the write endpoints.
	guard := func(next http.Handler) http.Handler {
		h := httpmw.MaxBytes(cfg.MaxBodyBytes)(next)
		h = httpmw.RateLimit(cfg.RateLimitRPS, cfg.RateLimitBurst)(h)
		return h
	}

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

// OpsConfig configures the operational server.
type OpsConfig struct {
	Addr        string
	EnablePprof bool
}

// NewOpsServer builds the operational server exposing /ping, /ready, and
// Prometheus /metrics, plus net/http/pprof when EnablePprof is set.
func NewOpsServer(cfg OpsConfig) *http.Server {
	if cfg.Addr == "" {
		cfg.Addr = DefaultOpsAddr
	}
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", ok)
	mux.HandleFunc("/ready", ok)
	mux.Handle("/metrics", promhttp.Handler())
	if cfg.EnablePprof {
		mux.HandleFunc("/debug/pprof/", nethttppprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", nethttppprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", nethttppprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", nethttppprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", nethttppprof.Trace)
	}

	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: DefaultTimeout,
	}
}
