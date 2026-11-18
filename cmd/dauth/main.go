// dauth is DIMO's identity and access token service. One binary serves two
// surfaces on one host (e.g. dauth.dimo.zone), routed by path prefix:
//
//   - /signin    a DID signs a challenge with a key its DID document lists
//     and gets a short-lived RS256 identity token whose sub is
//     the DID. The org host accepts these as member identity.
//   - /exchange  swaps an identity token plus a DPoP proof for an access
//     token scoped to one vehicle, after the org host has evaluated
//     the named delegation for that caller.
//
// Each surface signs with its own keyset and publishes its own JWKS + OIDC
// discovery under its prefix (/signin/keys, /exchange/keys); their iss claims
// stay distinct.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/DIMO-Network/dauth/internal/exchange"
	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/DIMO-Network/dauth/internal/ops"
	"github.com/DIMO-Network/dauth/internal/signin/config"
	"github.com/DIMO-Network/dauth/internal/signin/nonce"
	"github.com/DIMO-Network/dauth/internal/signin/server"
	"github.com/DIMO-Network/dauth/internal/signin/token"
	"github.com/DIMO-Network/dauth/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// maxOutstandingChallenges bounds the in-memory nonce store. At ~400 bytes per
// challenge this is well under 100 MiB even when full, and full only happens
// under a challenge flood, where rejecting new challenges is the right answer.
const maxOutstandingChallenges = 100_000

// selfTokenTTL is the lifetime of the identity token dauth mints for itself
// to call the org host with; it is renewed before it runs out.
const selfTokenTTL = 5 * time.Minute

func main() {
	log := zerolog.New(os.Stdout).With().Timestamp().Str("app", "dauth").Logger()
	if err := run(log); err != nil {
		log.Fatal().Err(err).Msg("dauth exited with error")
	}
}

func run(log zerolog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	exchangeCfg, err := exchange.Load()
	if err != nil {
		return fmt.Errorf("loading exchange config: %w", err)
	}
	if level, err := zerolog.ParseLevel(cfg.LogLevel); err == nil {
		zerolog.SetGlobalLevel(level)
	}
	zerolog.DefaultContextLogger = &log

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Sign-in (/signin) surface -------------------------------------------
	signinKeys, err := keyset.Load(cfg.SigningKeys)
	if err != nil {
		return err
	}
	issuer := token.NewIssuer(token.Config{Keys: signinKeys, Issuer: cfg.Issuer, Audience: cfg.Audience, TTL: cfg.TokenTTL})
	signinHandler, err := buildSignin(ctx, cfg, relyingParties(cfg, exchangeCfg), signinKeys, issuer, log)
	if err != nil {
		return err
	}

	// --- Exchange (/exchange) surface ----------------------------------------
	// The exchange validates the inbound identity token against the /signin
	// keyset in-process, and calls the org host as its own DID with a token
	// from the same issuer.
	signinJWKS, err := signinKeys.JWKS()
	if err != nil {
		return err
	}
	identity, err := exchange.NewIdentityVerifier(signinJWKS, cfg.Issuer, cfg.PublicBaseURL+"/exchange")
	if err != nil {
		return err
	}
	exchangeSurface, err := buildExchange(cfg, exchangeCfg, issuer, identity, log)
	if err != nil {
		return fmt.Errorf("building exchange surface: %w", err)
	}

	// --- Compose one public handler ------------------------------------------
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", healthCheck)
	mux.Handle("/signin/", http.StripPrefix("/signin", signinHandler))
	mux.Handle("POST /exchange", exchangeSurface.Exchange)
	mux.Handle("/exchange/", http.StripPrefix("/exchange", exchangeSurface.WellKnown))
	publicHandler := httpmw.Recover(log)(mux)

	publicSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           publicHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	opsSrv := ops.NewServer(ops.Config{Addr: cfg.OpsAddr, EnablePprof: exchangeCfg.EnablePprof})

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serveHTTP(gctx, publicSrv, log) })
	group.Go(func() error { return serveHTTP(gctx, opsSrv, log) })

	log.Info().
		Str("http", cfg.HTTPAddr).Str("ops", cfg.OpsAddr).
		Str("public_base_url", cfg.PublicBaseURL).Str("directory", cfg.DirectoryURL).
		Str("signin_issuer", cfg.Issuer).Str("signin_active_kid", signinKeys.ActiveKID()).
		Str("exchange_issuer", exchangeCfg.Issuer).Str("org_host", exchangeCfg.OrgHostURL).Str("dauth_did", exchangeCfg.DauthDID).
		Msg("dauth started")
	return group.Wait()
}

// buildSignin constructs the sign-in surface handler from an already-loaded
// keyset and issuer.
func buildSignin(ctx context.Context, cfg config.Config, audiences []string, keys *keyset.KeySet, issuer *token.Issuer, log zerolog.Logger) (http.Handler, error) {
	store, err := newStore(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	handlers := &server.Handlers{
		Store:            store,
		Verifier:         &server.Verifier{Directory: &server.DirectoryClient{Client: client.New(cfg.DirectoryURL)}},
		Issuer:           issuer,
		Domain:           cfg.Domain,
		ChallengeTTL:     cfg.ChallengeTTL,
		AllowedAudiences: audiences,
		Log:              log,
	}

	wellKnown, err := oidc.NewWellKnown(oidc.Config{
		Issuer:  cfg.Issuer,
		JWKSURI: cfg.PublicBaseURL + "/signin/keys",
		Keys:    keys,
	})
	if err != nil {
		return nil, err
	}
	return server.NewHandler(server.Config{Handlers: handlers, WellKnown: wellKnown}), nil
}

// buildExchange constructs the exchange surface. dauth's own identity for the
// org host is a sign-in token for DAUTH_DID, minted here and renewed a minute
// before it expires.
func buildExchange(cfg config.Config, ecfg exchange.Config, issuer *token.Issuer, identity *exchange.IdentityVerifier, log zerolog.Logger) (exchange.Surface, error) {
	keys, err := keyset.Load(ecfg.SigningKeys)
	if err != nil {
		return exchange.Surface{}, fmt.Errorf("failed to load exchange signing keys: %w", err)
	}
	wellKnown, err := oidc.NewWellKnown(oidc.Config{
		Issuer:          ecfg.Issuer,
		JWKSURI:         cfg.PublicBaseURL + "/exchange/keys",
		Keys:            keys,
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "cnf", "grants"},
	})
	if err != nil {
		return exchange.Surface{}, err
	}

	var mu sync.Mutex
	var selfToken string
	var selfExp time.Time
	self := func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if selfToken != "" && time.Now().Before(selfExp.Add(-time.Minute)) {
			return selfToken, nil
		}
		tok, exp, err := issuer.IssueFor(ecfg.DauthDID, []string{ecfg.OrgHostURL}, selfTokenTTL)
		if err != nil {
			return "", err
		}
		selfToken, selfExp = tok, exp
		return selfToken, nil
	}

	exchangeURL := cfg.PublicBaseURL + "/exchange"
	h := &exchange.Handler{
		Config: ecfg,
		Keys:   keys,
		Host: &exchange.OrgHost{
			BaseURL:  ecfg.OrgHostURL,
			Identity: self,
			HTTP:     &http.Client{Timeout: ecfg.OrgHostTimeout},
		},
		Assertions: &exchange.AssertionVerifier{
			Keys:          &server.Verifier{Directory: &server.DirectoryClient{Client: client.New(cfg.DirectoryURL)}},
			Audience:      exchangeURL,
			IsUnavailable: func(err error) bool { return errors.Is(err, server.ErrDirectory) },
		},
		DPoP:        dpop.NewVerifier(),
		ExchangeURL: exchangeURL,
		Log:         log,
	}
	return exchange.NewSurface(h, identity, wellKnown), nil
}

// relyingParties is the audiences a sign-in may ask for: those configured,
// plus the two dauth itself knows need identity tokens of their own, the
// exchange and the org host. Each checks aud, so a token is only ever good
// where its holder asked for it to be.
func relyingParties(cfg config.Config, ecfg exchange.Config) []string {
	return append(slices.Clone(cfg.AllowedAudiences), cfg.PublicBaseURL+"/exchange", ecfg.OrgHostURL)
}

func healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":"Server is up and running"}`))
}

// newStore builds the challenge store. With a Postgres DSN configured it
// returns a shared, replica-safe store (and opens a connection pool closed when
// ctx is cancelled); otherwise it returns the in-memory store, which requires a
// single replica.
func newStore(ctx context.Context, cfg config.Config, log zerolog.Logger) (nonce.Store, error) {
	if !cfg.UsePostgres() {
		log.Warn().Msg("DATABASE_URL not set; using in-memory challenge store (dauth must run a single replica)")
		return nonce.NewMemory(ctx, maxOutstandingChallenges), nil
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
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
func serveHTTP(ctx context.Context, srv *http.Server, log zerolog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
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
