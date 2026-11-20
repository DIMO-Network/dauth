// Package config loads dauth's runtime configuration from the environment.
// Loading follows the din convention: pure env vars, defaults applied here,
// and fail-fast validation so a misconfigured deployment never starts.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/dauth/internal/envx"
)

// Config is the process-wide configuration plus the sign-in surface's own.
type Config struct {
	LogLevel string

	// HTTP servers. One public listener serves both the /signin and /exchange
	// surfaces; the ops listener serves probes + Prometheus. TLS terminates at
	// the ingress. There is no rate limit in dauth or in the chart's ingress.
	HTTPAddr string // HTTP_ADDRESS — public server (both prefixes)
	OpsAddr  string // OPS_ADDRESS  — probes + Prometheus

	// PublicBaseURL is the externally reachable origin of the service (e.g.
	// https://dauth.dimo.zone). It is the base for each surface's published
	// jwks_uri (/signin/keys and /exchange/keys), for the DPoP htu of
	// /exchange and the /signin DPoP htu, and by convention for the iss claims.
	// Required.
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

	// CORSOrigins are the browser origins allowed to call /signin
	// (SIGNIN_CORS_ORIGINS, comma-separated). Empty sends no CORS headers.
	// Each must be exactly what a browser sends in Origin: lowercase
	// scheme://host[:port], no path, no trailing slash, no wildcard.
	CORSOrigins []string

	// RateLimitPerSecond is the per-client-IP limit on POST /signin/challenge
	// and POST /signin/token together (SIGNIN_RATE_LIMIT_PER_SECOND, default 5;
	// 0 disables it). The burst is twice the rate.
	RateLimitPerSecond int

	// TrustedProxies are the peers whose X-Forwarded-For dauth believes when
	// it works out a client's IP (SIGNIN_TRUSTED_PROXIES, comma-separated
	// CIDRs or addresses). Empty means the TCP peer is the client.
	TrustedProxies []netip.Prefix

	// Lifetimes.
	ChallengeTTL time.Duration // CHALLENGE_TTL
	TokenTTL     time.Duration // TOKEN_TTL: identity tokens without the approve scope
	// ApproveTTL is APPROVE_TOKEN_TTL: tokens carrying approve, kept short.
	// Unset, it is the shorter of 5m and TokenTTL; set, it may not exceed
	// TokenTTL.
	ApproveTTL time.Duration

	// Signing keys (SIGNIN_SIGNING_KEY_n), in priority order: the first is the
	// active signer; the rest are retiring keys kept in the JWKS so their tokens
	// still verify during a rotation overlap window. Each is a PEM-encoded RSA
	// private key.
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
		LogLevel:         envx.String("LOG_LEVEL", "info"),
		HTTPAddr:         envx.String("HTTP_ADDRESS", "0.0.0.0:8080"),
		OpsAddr:          envx.String("OPS_ADDRESS", "0.0.0.0:8081"),
		PublicBaseURL:    os.Getenv("PUBLIC_BASE_URL"),
		DirectoryURL:     os.Getenv("DIRECTORY_URL"),
		Issuer:           os.Getenv("SIGNIN_ISSUER"),
		Domain:           os.Getenv("SIGNIN_DOMAIN"),
		Audience:         envx.List(os.Getenv("JWT_AUDIENCE")),
		AllowedAudiences: envx.List(os.Getenv("SIGNIN_ALLOWED_AUDIENCES")),
		CORSOrigins:      envx.List(os.Getenv("SIGNIN_CORS_ORIGINS")),
	}
	for _, o := range s.CORSOrigins {
		if !isOrigin(o) {
			return s, fmt.Errorf("SIGNIN_CORS_ORIGINS entries must be lowercase scheme://host[:port] with no path, trailing slash or wildcard, as a browser sends Origin; got %q", o)
		}
	}
	for _, a := range s.AllowedAudiences {
		if strings.HasSuffix(a, "/") {
			return s, fmt.Errorf("SIGNIN_ALLOWED_AUDIENCES entries must not end in '/': audiences are compared exactly, and clients send them without one; got %q", a)
		}
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
	if s.TokenTTL, err = envx.Duration("TOKEN_TTL", 15*time.Minute); err != nil {
		return s, err
	}
	// The approve default follows a short TOKEN_TTL down, so setting only
	// TOKEN_TTL below 5m does not trip the check below.
	if s.ApproveTTL, err = envx.Duration("APPROVE_TOKEN_TTL", min(5*time.Minute, s.TokenTTL)); err != nil {
		return s, err
	}

	for _, ttl := range []struct {
		name string
		d    time.Duration
	}{{"CHALLENGE_TTL", s.ChallengeTTL}, {"TOKEN_TTL", s.TokenTTL}, {"APPROVE_TOKEN_TTL", s.ApproveTTL}} {
		if ttl.d <= 0 {
			return s, fmt.Errorf("%s must be greater than zero, got %s", ttl.name, ttl.d)
		}
	}
	if s.ApproveTTL > s.TokenTTL {
		return s, fmt.Errorf("APPROVE_TOKEN_TTL (%s) must not exceed TOKEN_TTL (%s)", s.ApproveTTL, s.TokenTTL)
	}

	if s.RateLimitPerSecond, err = envx.Int("SIGNIN_RATE_LIMIT_PER_SECOND", 5); err != nil {
		return s, err
	}
	if s.RateLimitPerSecond < 0 {
		return s, fmt.Errorf("SIGNIN_RATE_LIMIT_PER_SECOND must be 0 (off) or more, got %d", s.RateLimitPerSecond)
	}
	for _, p := range envx.List(os.Getenv("SIGNIN_TRUSTED_PROXIES")) {
		prefix, err := parsePrefix(p)
		if err != nil {
			return s, fmt.Errorf("SIGNIN_TRUSTED_PROXIES entries must be CIDRs or IP addresses, got %q", p)
		}
		s.TrustedProxies = append(s.TrustedProxies, prefix)
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

// isOrigin reports whether o is a serialized origin as browsers send it:
// lowercase scheme://host[:port] and nothing else.
func isOrigin(o string) bool {
	if o != strings.ToLower(o) || strings.Contains(o, "*") {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return o == u.Scheme+"://"+u.Host
}

// parsePrefix reads a CIDR, or a bare address as a single-address prefix.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
