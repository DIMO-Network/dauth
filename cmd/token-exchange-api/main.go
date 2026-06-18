// token-exchange-api — exchanges a dauth address-control token for a permission
// token scoped to a DIMO asset, after validating on-chain/SACD access. Mirrors
// dauth/din house style: stdlib net/http, env config, errgroup-supervised
// servers, graceful shutdown.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	nethttppprof "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DIMO-Network/dauth/internal/tokenexchange/app"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/config"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

// @title                      DIMO Token Exchange API
// @version                    1.0
// @BasePath                   /v1
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
func main() {
	log := zerolog.New(os.Stdout).With().Timestamp().Str("app", "token-exchange-api").Logger()
	if err := run(log); err != nil {
		log.Fatal().Err(err).Msg("token-exchange-api exited with error")
	}
}

func run(log zerolog.Logger) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	if level, err := zerolog.ParseLevel(settings.LogLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	}
	zerolog.DefaultContextLogger = &log

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handler, grpcServer, err := app.CreateServers(log, &settings)
	if err != nil {
		return err
	}

	webSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", settings.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	opsSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", settings.MonPort),
		Handler:           opsMux(settings.EnablePprof),
		ReadHeaderTimeout: 10 * time.Second,
	}

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serveHTTP(gctx, webSrv, log) })
	group.Go(func() error { return serveHTTP(gctx, opsSrv, log) })
	group.Go(func() error { return serveGRPC(gctx, grpcServer, fmt.Sprintf(":%d", settings.GRPCPort), log) })

	log.Info().Int("http", settings.Port).Int("grpc", settings.GRPCPort).Int("ops", settings.MonPort).
		Str("issuer", settings.Issuer).Msg("token-exchange-api started")
	return group.Wait()
}

// opsMux serves liveness/readiness probes and Prometheus metrics.
func opsMux(enablePprof bool) http.Handler {
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", ok)
	mux.HandleFunc("/ready", ok)
	mux.Handle("/metrics", promhttp.Handler())
	if enablePprof {
		mux.HandleFunc("/debug/pprof/", nethttppprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", nethttppprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", nethttppprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", nethttppprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", nethttppprof.Trace)
	}
	return mux
}

// serveHTTP runs srv until ctx cancels, then shuts it down gracefully.
func serveHTTP(ctx context.Context, srv *http.Server, log zerolog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Warn().Err(err).Str("addr", srv.Addr).Msg("graceful shutdown failed")
		}
		return nil
	}
}

// serveGRPC runs the gRPC server until ctx cancels, then stops it gracefully.
func serveGRPC(ctx context.Context, srv *grpc.Server, addr string, _ zerolog.Logger) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc listen on %s: %w", addr, err)
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(lis); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		srv.GracefulStop()
		return nil
	}
}
