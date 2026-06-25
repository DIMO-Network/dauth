// dauth — DIMO's Web3 auth service. One binary serves two surfaces on one host
// (e.g. dauth.dimo.zone), routed by path prefix:
//
//   - /siwe         sign-in: a wallet signs a Sign-In With Ethereum (EIP-4361)
//     challenge (EOA or deployed EIP-1271 smart account) and gets
//     a short-lived RS256 token identifying its Ethereum address.
//   - /exchange     swaps that sign-in token for a permission token scoped
//     to a DIMO asset, after an on-chain SACD access check.
//
// Each surface signs with its own keyset and publishes its own JWKS + OIDC
// discovery under its prefix (/siwe/keys, /exchange/keys); their iss claims
// stay distinct. A gRPC TokenExchangeService runs on its own port.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DIMO-Network/dauth/internal/config"
	_ "github.com/DIMO-Network/dauth/internal/docs" // registers the sign-in OpenAPI spec (instance "dauth")
	exchangeapp "github.com/DIMO-Network/dauth/internal/exchange/app"
	exchangeconfig "github.com/DIMO-Network/dauth/internal/exchange/config"
	"github.com/DIMO-Network/dauth/internal/exchange/middleware"
	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/nonce"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/DIMO-Network/dauth/internal/server"
	"github.com/DIMO-Network/dauth/internal/signer"
	"github.com/DIMO-Network/dauth/internal/token"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

// maxOutstandingChallenges bounds the in-memory nonce store. At ~400 bytes per
// challenge this is well under 100 MiB even when full, and full only happens
// under a challenge flood, where rejecting new challenges is the right answer.
const maxOutstandingChallenges = 100_000

// The two surfaces each have their own OpenAPI spec: the sign-in spec below
// (instance "dauth", served at /siwe/swagger/) and the exchange spec (instance
// "swagger", served at /exchange/swagger/) whose annotations live under
// internal/exchange. Distinct instance names keep them from colliding in
// this shared module.
//
// @title       dauth sign-in API
// @version     1.0
// @description DIMO Web3 sign-in. A client signs a Sign-In With Ethereum
// @description (EIP-4361) challenge and receives a short-lived RS256 JWT carrying
// @description its Ethereum address, verifiable offline against the published JWKS.
// @BasePath    /siwe
//
//go:generate go tool swag init -g main.go -d ./cmd/dauth,./internal/server -o ./internal/docs --instanceName dauth --parseInternal
func main() {
	log := zerolog.New(os.Stdout).With().Timestamp().Str("app", "dauth").Logger()
	if err := run(log); err != nil {
		log.Fatal().Err(err).Msg("dauth exited with error")
	}
}

func run(log zerolog.Logger) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	exchangeSettings, err := exchangeconfig.Load()
	if err != nil {
		return fmt.Errorf("loading exchange settings: %w", err)
	}
	if level, err := zerolog.ParseLevel(settings.LogLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	}
	zerolog.DefaultContextLogger = &log

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Sign-in (/siwe) surface ---------------------------------------------
	siweKeys, err := keyset.Load(settings.SigningKeys)
	if err != nil {
		return err
	}
	siweHandler, err := buildSIWE(ctx, settings, siweKeys, log)
	if err != nil {
		return err
	}

	// --- Exchange (/exchange) surface ----------------------------------------
	// The exchange validates the inbound sign-in token against the /siwe keyset
	// in-process — no HTTP fetch of our own not-yet-listening /siwe/keys.
	siweJWKS, err := siweKeys.JWKS()
	if err != nil {
		return err
	}
	jwtAuth, err := middleware.NewJWTAuthFromJWKS(siweJWKS)
	if err != nil {
		return err
	}
	exchangeHandler, grpcServer, err := exchangeapp.CreateServers(log, &exchangeSettings, settings.PublicBaseURL+"/exchange/keys", jwtAuth)
	if err != nil {
		return fmt.Errorf("building exchange surface: %w", err)
	}

	// --- Compose one public handler ------------------------------------------
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", healthCheck)
	mux.Handle("/siwe/", http.StripPrefix("/siwe", siweHandler))
	mux.Handle("/exchange/", http.StripPrefix("/exchange", exchangeHandler))
	publicHandler := httpmw.Recover(log)(mux)

	publicSrv := &http.Server{
		Addr:              settings.HTTPAddr,
		Handler:           publicHandler,
		ReadHeaderTimeout: server.DefaultTimeout,
	}
	useTLS := settings.TLSCertFile != ""
	if useTLS {
		cert, err := loadTLS(settings.TLSCertFile, settings.TLSKeyFile)
		if err != nil {
			return err
		}
		publicSrv.TLSConfig = cert
	}

	opsSrv := server.NewOpsServer(server.OpsConfig{Addr: settings.OpsAddr, EnablePprof: exchangeSettings.EnablePprof})

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serveHTTP(gctx, publicSrv, useTLS, log) })
	group.Go(func() error { return serveHTTP(gctx, opsSrv, false, log) })
	group.Go(func() error { return serveGRPC(gctx, grpcServer, fmt.Sprintf(":%d", exchangeSettings.GRPCPort), log) })

	log.Info().
		Str("http", settings.HTTPAddr).Str("ops", settings.OpsAddr).Int("grpc", exchangeSettings.GRPCPort).
		Str("public_base_url", settings.PublicBaseURL).
		Str("siwe_issuer", settings.Issuer).Str("siwe_active_kid", siweKeys.ActiveKID()).
		Str("exchange_issuer", exchangeSettings.Issuer).
		Msg("dauth started")
	return group.Wait()
}

// buildSIWE constructs the sign-in surface handler from an already-loaded
// keyset.
func buildSIWE(ctx context.Context, settings config.Settings, keys *keyset.KeySet, log zerolog.Logger) (http.Handler, error) {
	// EIP-1271 (smart-account) verification needs an RPC backend. Without one
	// the service still verifies EOA signatures.
	var backend bind.ContractBackend
	if settings.RPCURL != "" {
		client, err := ethclient.Dial(settings.RPCURL)
		if err != nil {
			return nil, err
		}
		// The client lives for the process; release it on shutdown.
		go func() { <-ctx.Done(); client.Close() }()
		backend = client
	} else {
		log.Warn().Msg("RPC_URL not set; smart-account (EIP-1271) sign-in is disabled")
	}

	store, err := newStore(ctx, settings, log)
	if err != nil {
		return nil, err
	}

	handlers := &server.Handlers{
		Store:    store,
		Verifier: signer.New(backend, log),
		Issuer: token.NewIssuer(token.Config{
			Keys:     keys,
			Issuer:   settings.Issuer,
			Audience: settings.Audience,
			TTL:      settings.TokenTTL,
		}),
		Domain:       settings.Domain,
		URI:          settings.PublicBaseURL,
		Statement:    settings.Statement,
		ChainID:      settings.ChainID,
		ChallengeTTL: settings.ChallengeTTL,
		Log:          log,
	}

	wellKnown, err := oidc.NewWellKnown(oidc.Config{
		Issuer:          settings.Issuer,
		JWKSURI:         settings.PublicBaseURL + "/siwe/keys",
		Keys:            keys,
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "ethereum_address"},
	})
	if err != nil {
		return nil, err
	}

	handler := server.NewSIWEHandler(server.SIWEConfig{
		Handlers:       handlers,
		WellKnown:      wellKnown,
		MaxBodyBytes:   settings.MaxBodyBytes,
		RateLimitRPS:   settings.RateLimitRPS,
		RateLimitBurst: settings.RateLimitBurst,
	})
	return handler, nil
}

func healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":"Server is up and running"}`))
}

// loadTLS builds a TLS config for in-process termination. The usual deployment
// terminates TLS at the ingress and leaves cert/key unset.
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS key pair: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}

// newStore builds the challenge store. With a Postgres DSN configured it
// returns a shared, replica-safe store (and opens a connection pool closed when
// ctx is cancelled); otherwise it returns the in-memory store, which requires a
// single replica.
func newStore(ctx context.Context, settings config.Settings, log zerolog.Logger) (nonce.Store, error) {
	if !settings.UsePostgres() {
		log.Warn().Msg("DATABASE_URL not set; using in-memory challenge store (dauth must run a single replica)")
		return nonce.NewMemory(ctx, maxOutstandingChallenges), nil
	}

	pool, err := pgxpool.New(ctx, settings.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening challenge database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting to challenge database: %w", err)
	}
	// The pool lives for the process; release it on shutdown.
	go func() {
		<-ctx.Done()
		pool.Close()
	}()

	store, err := nonce.NewPostgres(ctx, pool, log)
	if err != nil {
		return nil, err
	}
	cc := pool.Config().ConnConfig
	log.Info().Str("db_host", cc.Host).Str("db_name", cc.Database).
		Msg("using Postgres challenge store")
	return store, nil
}

// serveHTTP runs srv until ctx cancels, then shuts it down gracefully.
func serveHTTP(ctx context.Context, srv *http.Server, useTLS bool, log zerolog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
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
