// dauth — DIMO authentication service. Clients sign a Sign-In With Ethereum
// (EIP-4361) challenge with an EOA or a deployed smart account (EIP-1271); in
// return they get a short-lived RS256 access token identifying their Ethereum
// address. The token is verifiable offline against the JWKS and OIDC discovery
// document this service publishes.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DIMO-Network/dauth/internal/config"
	_ "github.com/DIMO-Network/dauth/internal/docs" // registers the generated OpenAPI spec (instance "dauth")
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/nonce"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/DIMO-Network/dauth/internal/server"
	"github.com/DIMO-Network/dauth/internal/signer"
	"github.com/DIMO-Network/dauth/internal/token"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// maxOutstandingChallenges bounds the in-memory nonce store. At ~400 bytes per
// challenge this is well under 100 MiB even when full, and full only happens
// under a challenge flood, where rejecting new challenges is the right answer.
const maxOutstandingChallenges = 100_000

// @title       dauth API
// @version     1.0
// @description DIMO Web3 sign-in. A client signs a Sign-In With Ethereum
// @description (EIP-4361) challenge and receives a short-lived RS256 JWT carrying
// @description its Ethereum address, verifiable offline against the published JWKS.
// @BasePath    /
//
// The spec is generated into a dauth-specific package under the instance name
// "dauth" so it never collides with token-exchange-api's spec (instance
// "swagger") in this shared module. The exclude keeps tokenexchange routes out.
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
	if level, err := zerolog.ParseLevel(settings.LogLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	keys, err := keyset.Load(settings.SigningKeys)
	if err != nil {
		return err
	}

	// EIP-1271 (smart-account) verification needs an RPC backend. Without one
	// the service still verifies EOA signatures.
	var backend bind.ContractBackend
	if settings.RPCURL != "" {
		client, err := ethclient.Dial(settings.RPCURL)
		if err != nil {
			return err
		}
		defer client.Close()
		backend = client
	} else {
		log.Warn().Msg("RPC_URL not set; smart-account (EIP-1271) sign-in is disabled")
	}

	handlers := &server.Handlers{
		Store:    nonce.NewMemory(ctx, maxOutstandingChallenges),
		Verifier: signer.New(backend, log),
		Issuer: token.NewIssuer(token.Config{
			Keys:     keys,
			Issuer:   settings.Issuer,
			Audience: settings.Audience,
			TTL:      settings.TokenTTL,
		}),
		Domain:       settings.Domain,
		URI:          settings.Issuer,
		Statement:    settings.Statement,
		ChainID:      settings.ChainID,
		ChallengeTTL: settings.ChallengeTTL,
		Log:          log,
	}

	wellKnown, err := oidc.NewWellKnown(oidc.Config{
		Issuer:          settings.Issuer,
		JWKSURI:         settings.Issuer + "/keys",
		Keys:            keys,
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "ethereum_address"},
	})
	if err != nil {
		return err
	}

	authSrv, err := server.NewAuthServer(server.AuthConfig{
		Addr:           settings.AuthAddr,
		Handlers:       handlers,
		WellKnown:      wellKnown,
		MaxBodyBytes:   settings.MaxBodyBytes,
		RateLimitRPS:   settings.RateLimitRPS,
		RateLimitBurst: settings.RateLimitBurst,
		TLSCertFile:    settings.TLSCertFile,
		TLSKeyFile:     settings.TLSKeyFile,
		Logger:         log,
	})
	if err != nil {
		return err
	}
	opsSrv := server.NewOpsServer(server.OpsConfig{Addr: settings.OpsAddr})
	useTLS := settings.TLSCertFile != ""

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serveHTTP(gctx, authSrv, useTLS, log) })
	group.Go(func() error { return serveHTTP(gctx, opsSrv, false, log) })

	log.Info().Str("auth", settings.AuthAddr).Str("ops", settings.OpsAddr).
		Str("issuer", settings.Issuer).Str("active_kid", keys.ActiveKID()).
		Bool("eip1271", backend != nil).Msg("dauth started")
	return group.Wait()
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
