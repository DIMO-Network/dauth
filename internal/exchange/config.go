package exchange

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/dauth/internal/envx"
)

// Config is the exchange surface's configuration.
type Config struct {
	// Issuer is the iss claim of access tokens (e.g.
	// https://dauth.dimo.zone/exchange). Required.
	Issuer string
	// Audience is the default aud of access tokens: the services that accept
	// them. EXCHANGE_AUDIENCE, comma-separated; defaults to "dq".
	Audience []string
	// SigningKeys are the PEM RSA keys, EXCHANGE_SIGNING_KEY_1... in priority
	// order. Required.
	SigningKeys []string

	// OrgHostURL is the org host whose /authorize decides what a caller may
	// do (plan §1 decision A). Required.
	OrgHostURL string
	// OrgHostTimeout bounds one /authorize call. ORG_HOST_TIMEOUT, default 10s.
	OrgHostTimeout time.Duration
	// DauthDID is the DID dauth presents to the org host, which lists it in
	// ISSUER_DIDS. Required.
	DauthDID string

	// LiveTTL and HistoricalTTL are the access token lifetimes (spec §11.1):
	// 15 minutes when the token carries any live ability, 2 hours otherwise.
	LiveTTL       time.Duration
	HistoricalTTL time.Duration

	// EnablePprof exposes /debug/pprof on the ops server.
	EnablePprof bool
}

// Load reads Config from the environment.
func Load() (Config, error) {
	c := Config{
		Issuer:      os.Getenv("EXCHANGE_ISSUER"),
		Audience:    envx.List(envx.String("EXCHANGE_AUDIENCE", "dq")),
		OrgHostURL:  os.Getenv("ORG_HOST_URL"),
		DauthDID:    os.Getenv("DAUTH_DID"),
		EnablePprof: envx.String("ENABLE_PPROF", "false") == "true",
	}
	if c.Issuer == "" {
		return c, errors.New("EXCHANGE_ISSUER is required (e.g. https://dauth.dimo.zone/exchange)")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return c, fmt.Errorf("EXCHANGE_ISSUER must be an absolute URL, got %q", c.Issuer)
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")

	if c.OrgHostURL == "" {
		return c, errors.New("ORG_HOST_URL is required (the org host that answers /authorize)")
	}
	if u, err := url.Parse(c.OrgHostURL); err != nil || u.Scheme == "" || u.Host == "" {
		return c, fmt.Errorf("ORG_HOST_URL must be an absolute URL, got %q", c.OrgHostURL)
	}
	c.OrgHostURL = strings.TrimRight(c.OrgHostURL, "/")

	if !strings.HasPrefix(c.DauthDID, "did:") || len(c.DauthDID) == len("did:") {
		return c, errors.New("DAUTH_DID is required: the DID dauth presents to the org host")
	}

	if c.OrgHostTimeout, err = envx.Duration("ORG_HOST_TIMEOUT", 10*time.Second); err != nil {
		return c, err
	}
	if c.LiveTTL, err = envx.Duration("EXCHANGE_LIVE_TTL", 15*time.Minute); err != nil {
		return c, err
	}
	if c.HistoricalTTL, err = envx.Duration("EXCHANGE_HISTORICAL_TTL", 2*time.Hour); err != nil {
		return c, err
	}

	c.SigningKeys = envx.Numbered("EXCHANGE_SIGNING_KEY_")
	if len(c.SigningKeys) == 0 {
		return c, errors.New("at least one signing key is required (EXCHANGE_SIGNING_KEY_1, EXCHANGE_SIGNING_KEY_2, ...)")
	}
	return c, nil
}
