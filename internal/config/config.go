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
	"github.com/DIMO-Network/shared/pkg/db"
)

// Settings is the full runtime configuration.
type Settings struct {
	Environment string
	LogLevel    string

	// HTTP servers. One public listener serves both the /siwe and /permissions
	// surfaces; the ops listener serves probes + Prometheus.
	HTTPAddr       string // HTTP_ADDRESS — public server (both prefixes)
	OpsAddr        string // OPS_ADDRESS  — probes + Prometheus
	TLSCertFile    string // optional; TLS usually terminates at the ingress
	TLSKeyFile     string
	MaxBodyBytes   int64
	RateLimitRPS   float64
	RateLimitBurst int

	// PublicBaseURL is the externally reachable origin of the merged service
	// (e.g. https://dauth.dimo.zone). It is the base for each surface's published
	// jwks_uri — https://dauth.dimo.zone/siwe/keys and /permissions/keys — and,
	// by convention, for the iss claims (https://dauth.dimo.zone/siwe and
	// /permissions), so each surface's discovery document is self-consistent.
	// Required.
	PublicBaseURL string

	// Token / issuer identity for the sign-in (/siwe) surface.
	Issuer    string   // SIWE_ISSUER (e.g. https://dauth.dimo.zone/siwe) — required
	Domain    string   // SIWE_DOMAIN host; defaults to the PublicBaseURL host
	Audience  []string // JWT_AUDIENCE (comma-separated) — required
	Statement string   // SIWE_STATEMENT shown in the wallet prompt

	// Chain the sign-in is bound to — the Chain ID in the SIWE message. DIMO
	// runs on a single chain, so this is one value, not a per-request field.
	ChainID uint64 // CHAIN_ID

	// Lifetimes.
	ChallengeTTL      time.Duration // CHALLENGE_TTL
	TokenTTL          time.Duration // TOKEN_TTL
	AllowableTimeSkew time.Duration // ALLOWABLE_TIME_SKEW

	// Smart-account (EIP-1271) verification.
	RPCURL     string        // RPC_URL; empty disables contract-signature checks
	RPCTimeout time.Duration // RPC_TIMEOUT

	// Signing keys, in priority order: the first is the active signer; the
	// rest are retiring keys kept in the JWKS so their tokens still verify
	// during a rotation overlap window. Each is a PEM-encoded RSA private key.
	SigningKeys []string

	// DB configures the Postgres-backed challenge store. It is engaged only when
	// DB.Host is set; otherwise dauth uses the in-memory store and must run a
	// single replica. A shared store is what allows more than one replica.
	DB db.Settings
}

// UsePostgres reports whether a Postgres challenge store is configured. When
// false, dauth falls back to the single-replica in-memory store.
func (s Settings) UsePostgres() bool { return s.DB.Host != "" }

// Load reads Settings from the environment, applying defaults, and fails if a
// required value is missing or malformed.
func Load() (Settings, error) {
	s := Settings{
		Environment:   envx.String("ENVIRONMENT", "dev"),
		LogLevel:      envx.String("LOG_LEVEL", "info"),
		HTTPAddr:      envx.String("HTTP_ADDRESS", "0.0.0.0:8080"),
		OpsAddr:       envx.String("OPS_ADDRESS", "0.0.0.0:8081"),
		TLSCertFile:   os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:    os.Getenv("TLS_KEY_FILE"),
		PublicBaseURL: os.Getenv("PUBLIC_BASE_URL"),
		Issuer:        os.Getenv("SIWE_ISSUER"),
		Domain:        os.Getenv("SIWE_DOMAIN"),
		Statement:     envx.String("SIWE_STATEMENT", "Sign in to DIMO."),
		RPCURL:        os.Getenv("RPC_URL"),
		Audience:      envx.List(os.Getenv("JWT_AUDIENCE")),
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

	maxBody, err := envx.Uint("MAX_BODY_BYTES", 16<<10) // 16 KiB; bodies are tiny JSON
	if err != nil {
		return s, err
	}
	s.MaxBodyBytes = int64(maxBody)

	rps, err := envx.Uint("RATE_LIMIT_RPS", 0)
	if err != nil {
		return s, err
	}
	s.RateLimitRPS = float64(rps)
	burst, err := envx.Uint("RATE_LIMIT_BURST", 20)
	if err != nil {
		return s, err
	}
	s.RateLimitBurst = int(burst)

	if s.ChallengeTTL, err = envx.Duration("CHALLENGE_TTL", 5*time.Minute); err != nil {
		return s, err
	}
	if s.TokenTTL, err = envx.Duration("TOKEN_TTL", time.Hour); err != nil {
		return s, err
	}
	if s.AllowableTimeSkew, err = envx.Duration("ALLOWABLE_TIME_SKEW", 5*time.Minute); err != nil {
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

	// Challenge store. DB_HOST opts into Postgres (and thus multiple replicas);
	// leaving it empty keeps the in-memory store. When it is set, the
	// credentials and database name must be present too — fail fast rather than
	// surface an opaque connection error at first sign-in.
	maxOpen, err := envx.Uint("DB_MAX_OPEN_CONNECTIONS", 10)
	if err != nil {
		return s, err
	}
	maxIdle, err := envx.Uint("DB_MAX_IDLE_CONNECTIONS", 5)
	if err != nil {
		return s, err
	}
	s.DB = db.Settings{
		Host:               os.Getenv("DB_HOST"),
		Port:               envx.String("DB_PORT", "5432"),
		User:               os.Getenv("DB_USER"),
		Password:           os.Getenv("DB_PASSWORD"),
		Name:               os.Getenv("DB_NAME"),
		SSLMode:            envx.String("DB_SSL_MODE", db.SSLModeRequire),
		MaxOpenConnections: int(maxOpen),
		MaxIdleConnections: int(maxIdle),
	}
	if s.UsePostgres() {
		if s.DB.User == "" || s.DB.Password == "" || s.DB.Name == "" {
			return s, errors.New("DB_HOST is set, so DB_USER, DB_PASSWORD, and DB_NAME are all required")
		}
	}

	return s, nil
}
