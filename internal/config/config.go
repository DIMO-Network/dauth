// Package config loads dauth's runtime configuration from the environment.
// Loading follows the din convention: pure env vars, defaults applied here,
// and fail-fast validation so a misconfigured deployment never starts.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Settings is the full runtime configuration.
type Settings struct {
	Environment string
	LogLevel    string

	// HTTP servers.
	AuthAddr       string // AUTH_ADDRESS — public login + JWKS server
	OpsAddr        string // OPS_ADDRESS  — probes + Prometheus
	TLSCertFile    string // optional; TLS usually terminates at the ingress
	TLSKeyFile     string
	MaxBodyBytes   int64
	RateLimitRPS   float64
	RateLimitBurst int

	// Token / issuer identity.
	Issuer    string   // ISSUER (e.g. https://auth.dimo.zone) — required
	Domain    string   // SIWE_DOMAIN host; defaults to the issuer host
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
}

// Load reads Settings from the environment, applying defaults, and fails if a
// required value is missing or malformed.
func Load() (Settings, error) {
	s := Settings{
		Environment: env("ENVIRONMENT", "dev"),
		LogLevel:    env("LOG_LEVEL", "info"),
		AuthAddr:    env("AUTH_ADDRESS", "0.0.0.0:8080"),
		OpsAddr:     env("OPS_ADDRESS", "0.0.0.0:8081"),
		TLSCertFile: os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("TLS_KEY_FILE"),
		Issuer:      os.Getenv("ISSUER"),
		Domain:      os.Getenv("SIWE_DOMAIN"),
		Statement:   env("SIWE_STATEMENT", "Sign in to DIMO."),
		RPCURL:      os.Getenv("RPC_URL"),
		Audience:    splitList(os.Getenv("JWT_AUDIENCE")),
	}

	if s.Issuer == "" {
		return s, errors.New("ISSUER is required (e.g. https://auth.dimo.zone)")
	}
	issuerURL, err := url.Parse(s.Issuer)
	if err != nil || issuerURL.Scheme == "" || issuerURL.Host == "" {
		return s, fmt.Errorf("ISSUER must be an absolute URL, got %q", s.Issuer)
	}
	// Trim any trailing slash so the issuer claim and discovery document are
	// byte-stable across deployments.
	s.Issuer = strings.TrimRight(s.Issuer, "/")
	if s.Domain == "" {
		s.Domain = issuerURL.Host
	}
	if len(s.Audience) == 0 {
		return s, errors.New("JWT_AUDIENCE is required (comma-separated audience list)")
	}

	if s.ChainID, err = envUint("CHAIN_ID", 137); err != nil {
		return s, err
	}

	maxBody, err := envUint("MAX_BODY_BYTES", 16<<10) // 16 KiB; bodies are tiny JSON
	if err != nil {
		return s, err
	}
	s.MaxBodyBytes = int64(maxBody)

	rps, err := envUint("RATE_LIMIT_RPS", 0)
	if err != nil {
		return s, err
	}
	s.RateLimitRPS = float64(rps)
	burst, err := envUint("RATE_LIMIT_BURST", 20)
	if err != nil {
		return s, err
	}
	s.RateLimitBurst = int(burst)

	if s.ChallengeTTL, err = envDuration("CHALLENGE_TTL", 5*time.Minute); err != nil {
		return s, err
	}
	if s.TokenTTL, err = envDuration("TOKEN_TTL", time.Hour); err != nil {
		return s, err
	}
	if s.AllowableTimeSkew, err = envDuration("ALLOWABLE_TIME_SKEW", 5*time.Minute); err != nil {
		return s, err
	}
	if s.RPCTimeout, err = envDuration("RPC_TIMEOUT", 3*time.Second); err != nil {
		return s, err
	}

	// Signing keys: SIGNING_KEY_1, SIGNING_KEY_2, ... in order. The first is
	// the active signer. At least one is required to mint tokens.
	s.SigningKeys = numberedEnv("SIGNING_KEY_")
	if len(s.SigningKeys) == 0 {
		return s, errors.New("at least one signing key is required (SIGNING_KEY_1, SIGNING_KEY_2, ...)")
	}

	return s, nil
}

// numberedEnv collects values from prefix+"1", prefix+"2", ... stopping at the
// first gap, so a contiguous, ordered key list comes straight from the
// environment without a separate count variable.
func numberedEnv(prefix string) []string {
	var out []string
	for i := 1; ; i++ {
		v := os.Getenv(prefix + strconv.Itoa(i))
		if v == "" {
			break
		}
		out = append(out, v)
	}
	return out
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envUint(key string, def uint64) (uint64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return d, nil
}
