// Package config loads dauth's runtime configuration from the environment.
// Loading follows the din convention: pure env vars, defaults applied here,
// and fail-fast validation so a misconfigured deployment never starts.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/dauth/internal/envx"
)

// Config is the full runtime configuration.
type Config struct {
	Environment string
	LogLevel    string

	// HTTP servers. One public listener serves both the /siwe and /exchange
	// surfaces; the ops listener serves probes + Prometheus. TLS termination,
	// rate limiting, and request-size limits are handled at the ingress.
	HTTPAddr string // HTTP_ADDRESS — public server (both prefixes)
	OpsAddr  string // OPS_ADDRESS  — probes + Prometheus

	// PublicBaseURL is the externally reachable origin of the merged service
	// (e.g. https://dauth.dimo.zone). It is the base for each surface's published
	// jwks_uri — https://dauth.dimo.zone/siwe/keys and /exchange/keys — and,
	// by convention, for the iss claims (https://dauth.dimo.zone/siwe and
	// /exchange), so each surface's discovery document is self-consistent.
	// Required.
	PublicBaseURL string

	// Token / issuer identity for the sign-in (/siwe) surface.
	Issuer    string   // SIWE_ISSUER (e.g. https://dauth.dimo.zone/siwe) — required
	Domain    string   // SIWE_DOMAIN host; defaults to the PublicBaseURL host
	Audience  []string // JWT_AUDIENCE (comma-separated) — required; the default aud
	Statement string   // SIWE_STATEMENT shown in the wallet prompt

	// AllowedAudiences is the allow-list of non-default `aud` values a caller may
	// request at /siwe/challenge (SIWE_ALLOWED_AUDIENCES, comma-separated). A
	// requested audience is honored only if every value appears here; otherwise
	// the challenge is rejected. Empty (the default) means no override is
	// permitted and every token carries the configured Audience. This exists to
	// let specific clients — e.g. step-ca cert enrollment, which validates the
	// sign-in token as an id_token and requires its own clientID in `aud` — mint
	// a sign-in token they can consume, without changing the default.
	AllowedAudiences []string // SIWE_ALLOWED_AUDIENCES (comma-separated) — optional

	// Chain the sign-in is bound to — the Chain ID in the SIWE message. DIMO
	// runs on a single chain, so this is one value, not a per-request field.
	ChainID uint64 // CHAIN_ID

	// Lifetimes.
	ChallengeTTL time.Duration // CHALLENGE_TTL
	TokenTTL     time.Duration // TOKEN_TTL

	// Smart-account (EIP-1271) verification.
	RPCURL     string        // RPC_URL; empty disables contract-signature checks
	RPCTimeout time.Duration // RPC_TIMEOUT

	// Signing keys, in priority order: the first is the active signer; the
	// rest are retiring keys kept in the JWKS so their tokens still verify
	// during a rotation overlap window. Each is a PEM-encoded RSA private key.
	SigningKeys []string

	// DatabaseURL is the pgx connection URL for the Postgres-backed challenge
	// store (e.g. postgres://user:pass@host:5432/dauth?sslmode=require). It is
	// engaged only when set; otherwise dauth uses the in-memory store and must
	// run a single replica. A shared store is what allows more than one replica.
	// Pool sizing is tuned inline via pgx query params, e.g. ?pool_max_conns=10.
	DatabaseURL string
}

// UsePostgres reports whether a Postgres challenge store is configured. When
// false, dauth falls back to the single-replica in-memory store.
func (s Config) UsePostgres() bool { return s.DatabaseURL != "" }

// Load reads Config from the environment, applying defaults, and fails if a
// required value is missing or malformed.
func Load() (Config, error) {
	s := Config{
		Environment:      envx.String("ENVIRONMENT", "dev"),
		LogLevel:         envx.String("LOG_LEVEL", "info"),
		HTTPAddr:         envx.String("HTTP_ADDRESS", "0.0.0.0:8080"),
		OpsAddr:          envx.String("OPS_ADDRESS", "0.0.0.0:8081"),
		PublicBaseURL:    os.Getenv("PUBLIC_BASE_URL"),
		Issuer:           os.Getenv("SIWE_ISSUER"),
		Domain:           os.Getenv("SIWE_DOMAIN"),
		Statement:        envx.String("SIWE_STATEMENT", "Sign in to DIMO."),
		RPCURL:           os.Getenv("RPC_URL"),
		Audience:         envx.List(os.Getenv("JWT_AUDIENCE")),
		AllowedAudiences: envx.List(os.Getenv("SIWE_ALLOWED_AUDIENCES")),
	}

	if s.Issuer == "" {
		return s, errors.New("SIWE_ISSUER is required (e.g. https://dauth.dimo.zone/siwe)")
	}
	issuerURL, err := url.Parse(s.Issuer)
	if err != nil || issuerURL.Scheme == "" || issuerURL.Host == "" {
		return s, fmt.Errorf("SIWE_ISSUER must be an absolute URL, got %q", s.Issuer)
	}
	// Trim any trailing slash so the issuer claim and discovery document are
	// byte-stable across deployments.
	s.Issuer = strings.TrimRight(s.Issuer, "/")

	if s.PublicBaseURL == "" {
		return s, errors.New("PUBLIC_BASE_URL is required (e.g. https://dauth.dimo.zone)")
	}
	publicURL, err := url.Parse(s.PublicBaseURL)
	if err != nil || publicURL.Scheme == "" || publicURL.Host == "" {
		return s, fmt.Errorf("PUBLIC_BASE_URL must be an absolute URL, got %q", s.PublicBaseURL)
	}
	s.PublicBaseURL = strings.TrimRight(s.PublicBaseURL, "/")
	// The SIWE message domain is the origin the user is signing in to — the
	// public host, not the iss claim's host.
	if s.Domain == "" {
		s.Domain = publicURL.Host
	}
	if len(s.Audience) == 0 {
		return s, errors.New("JWT_AUDIENCE is required (comma-separated audience list)")
	}

	if s.ChainID, err = envx.Uint("CHAIN_ID", 137); err != nil {
		return s, err
	}

	if s.ChallengeTTL, err = envx.Duration("CHALLENGE_TTL", 5*time.Minute); err != nil {
		return s, err
	}
	if s.TokenTTL, err = envx.Duration("TOKEN_TTL", time.Hour); err != nil {
		return s, err
	}
	if s.RPCTimeout, err = envx.Duration("RPC_TIMEOUT", 3*time.Second); err != nil {
		return s, err
	}

	// Signing keys: SIGNING_KEY_1, SIGNING_KEY_2, ... in order. The first is
	// the active signer. At least one is required to mint tokens.
	s.SigningKeys = envx.Numbered("SIWE_SIGNING_KEY_")
	if len(s.SigningKeys) == 0 {
		return s, errors.New("at least one signing key is required (SIWE_SIGNING_KEY_1, SIWE_SIGNING_KEY_2, ...)")
	}

	// Challenge store. DATABASE_URL opts into Postgres (and thus multiple
	// replicas); leaving it empty keeps the in-memory store. Validate the shape
	// here so a malformed URL fails at startup rather than at first sign-in;
	// pgx does the full parse when the pool opens.
	s.DatabaseURL = os.Getenv("DATABASE_URL")
	if s.UsePostgres() {
		u, err := url.Parse(s.DatabaseURL)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			return s, fmt.Errorf("DATABASE_URL must be a postgres:// connection URL, got %q", s.DatabaseURL)
		}
	}

	return s, nil
}
