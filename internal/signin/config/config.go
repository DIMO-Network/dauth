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

// Config is the process-wide configuration plus the sign-in surface's own.
type Config struct {
	Environment string
	LogLevel    string

	// HTTP servers. One public listener serves both the /signin and /exchange
	// surfaces; the ops listener serves probes + Prometheus. TLS termination,
	// rate limiting, and request-size limits are handled at the ingress.
	HTTPAddr string // HTTP_ADDRESS — public server (both prefixes)
	OpsAddr  string // OPS_ADDRESS  — probes + Prometheus

	// PublicBaseURL is the externally reachable origin of the service (e.g.
	// https://dauth.dimo.zone). It is the base for each surface's published
	// jwks_uri (/signin/keys and /exchange/keys), for the DPoP htu of
	// /exchange, and by convention for the iss claims. Required.
	PublicBaseURL string

	// DirectoryURL is the DID directory sign-in resolves DID documents from.
	// Required: a sign-in is a signature by a key the document lists.
	DirectoryURL string

	// Token / issuer identity for the sign-in (/signin) surface.
	Issuer   string   // SIGNIN_ISSUER (e.g. https://dauth.dimo.zone/signin) — required
	Domain   string   // SIGNIN_DOMAIN shown in the challenge; defaults to the PublicBaseURL host
	Audience []string // JWT_AUDIENCE (comma-separated) — required; the default aud

	// AllowedAudiences is the allow-list of non-default `aud` values a caller may
	// request at /signin/challenge (SIGNIN_ALLOWED_AUDIENCES, comma-separated).
	// A requested audience is honored only if every value appears here;
	// otherwise the challenge is rejected. Empty (the default) means no override
	// is permitted and every token carries the configured Audience.
	AllowedAudiences []string

	// Lifetimes.
	ChallengeTTL time.Duration // CHALLENGE_TTL
	TokenTTL     time.Duration // TOKEN_TTL

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
		DirectoryURL:     os.Getenv("DIRECTORY_URL"),
		Issuer:           os.Getenv("SIGNIN_ISSUER"),
		Domain:           os.Getenv("SIGNIN_DOMAIN"),
		Audience:         envx.List(os.Getenv("JWT_AUDIENCE")),
		AllowedAudiences: envx.List(os.Getenv("SIGNIN_ALLOWED_AUDIENCES")),
	}

	if s.Issuer == "" {
		return s, errors.New("SIGNIN_ISSUER is required (e.g. https://dauth.dimo.zone/signin)")
	}
	issuerURL, err := url.Parse(s.Issuer)
	if err != nil || issuerURL.Scheme == "" || issuerURL.Host == "" {
		return s, fmt.Errorf("SIGNIN_ISSUER must be an absolute URL, got %q", s.Issuer)
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
	// The challenge domain is the origin the user is signing in to: the public
	// host, not the iss claim's host.
	if s.Domain == "" {
		s.Domain = publicURL.Host
	}
	if len(s.Audience) == 0 {
		return s, errors.New("JWT_AUDIENCE is required (comma-separated audience list)")
	}

	if s.DirectoryURL == "" {
		return s, errors.New("DIRECTORY_URL is required (the DID directory sign-in resolves keys from)")
	}
	dirURL, err := url.Parse(s.DirectoryURL)
	if err != nil || dirURL.Scheme == "" || dirURL.Host == "" {
		return s, fmt.Errorf("DIRECTORY_URL must be an absolute URL, got %q", s.DirectoryURL)
	}
	s.DirectoryURL = strings.TrimRight(s.DirectoryURL, "/")

	if s.ChallengeTTL, err = envx.Duration("CHALLENGE_TTL", 5*time.Minute); err != nil {
		return s, err
	}
	if s.TokenTTL, err = envx.Duration("TOKEN_TTL", time.Hour); err != nil {
		return s, err
	}

	// Signing keys: SIGNIN_SIGNING_KEY_1, SIGNIN_SIGNING_KEY_2, ... in order. The
	// first is the active signer. At least one is required to mint tokens.
	s.SigningKeys = envx.Numbered("SIGNIN_SIGNING_KEY_")
	if len(s.SigningKeys) == 0 {
		return s, errors.New("at least one signing key is required (SIGNIN_SIGNING_KEY_1, SIGNIN_SIGNING_KEY_2, ...)")
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
