// Package ops wires the service-wide operational server (probes and Prometheus
// metrics) shared by both surfaces. It is independent of either surface's
// request handling: the merged binary runs one ops listener for the whole
// process.
package ops

import (
	"net/http"
	nethttppprof "net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	DefaultOpsAddr = ":8081"
	DefaultTimeout = 10 * time.Second
)

// Config configures the operational server.
type Config struct {
	Addr        string
	EnablePprof bool
}

// NewServer builds the operational server exposing /ping, /ready, and
// Prometheus /metrics, plus net/http/pprof when EnablePprof is set.
func NewServer(cfg Config) *http.Server {
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
