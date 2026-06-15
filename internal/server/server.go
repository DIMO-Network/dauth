// Package server wires dauth's HTTP surface: the public sign-in + JWKS server
// and the ops server (probes and Prometheus metrics). It follows din's
// conventions — standard net/http, explicit middleware composition, and
// constructors that return *http.Server for the caller's errgroup to run.
package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

const (
	DefaultAuthAddr     = ":8080"
	DefaultOpsAddr      = ":8081"
	DefaultTimeout      = 10 * time.Second
	DefaultMaxBodyBytes = 16 << 10 // 16 KiB
)

// AuthConfig configures the public sign-in server.
type AuthConfig struct {
	Addr           string
	Handlers       *Handlers
	WellKnown      *WellKnown
	MaxBodyBytes   int64
	RateLimitRPS   float64
	RateLimitBurst int
	// TLSCertFile/TLSKeyFile enable in-process TLS. Leave empty to terminate
	// TLS at the ingress (the default deployment).
	TLSCertFile string
	TLSKeyFile  string
	Timeout     time.Duration
	Logger      zerolog.Logger
}

// NewAuthServer builds the public server. The two POST routes are rate-limited
// and body-capped; the read-only discovery and JWKS routes are exempt so token
// validators polling the JWKS are never throttled. A panic recoverer wraps
// everything.
func NewAuthServer(cfg AuthConfig) (*http.Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAuthAddr
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}

	// Per-request guards applied only to the write endpoints.
	guard := func(next http.Handler) http.Handler {
		h := maxBytesMiddleware(cfg.MaxBodyBytes)(next)
		h = rateLimitMiddleware(cfg.RateLimitRPS, cfg.RateLimitBurst)(h)
		return h
	}

	mux := http.NewServeMux()
	mux.Handle("POST /auth/challenge", guard(cfg.Handlers.Challenge()))
	mux.Handle("POST /auth/token", guard(cfg.Handlers.Token()))
	mux.Handle("GET /.well-known/openid-configuration", cfg.WellKnown.Discovery())
	mux.Handle("GET /keys", cfg.WellKnown.JWKS())
	mux.Handle("GET /.well-known/jwks.json", cfg.WellKnown.JWKS())

	handler := recoverMiddleware(cfg.Logger)(mux)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadTimeout:       cfg.Timeout,
		ReadHeaderTimeout: cfg.Timeout,
		WriteTimeout:      cfg.Timeout,
	}

	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS key pair: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
	}
	return srv, nil
}

// OpsConfig configures the operational server.
type OpsConfig struct {
	Addr string
}

// NewOpsServer builds the operational server exposing /ping, /ready, and
// Prometheus /metrics.
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

	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: DefaultTimeout,
	}
}
