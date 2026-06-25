// Package oidc serves the standards-based token-validation surface shared by
// both surfaces: an OIDC discovery document and the JWKS. Neither the sign-in
// nor the exchange surface is a full OAuth2 authorization server — they issue tokens
// through their own flows and publish keys for offline validation — so the
// authorization and token endpoints are intentionally absent.
package oidc

import (
	"encoding/json"
	"net/http"

	"github.com/DIMO-Network/dauth/internal/keyset"
)

// Config describes the discovery/JWKS surface for one issuer.
type Config struct {
	// Issuer is the iss value and the base of the discovery document.
	Issuer string
	// JWKSURI is the absolute URL where the JWKS is served.
	JWKSURI string
	// Keys is the signing key set whose public halves are published.
	Keys *keyset.KeySet
	// ClaimsSupported lists the claims tokens may carry (advisory). Defaults to
	// the registered claim set if empty.
	ClaimsSupported []string
}

// WellKnown serves OIDC discovery and the JWKS. Both documents are static for
// the process lifetime (the key set is fixed at startup), so they are rendered
// once and served from memory with cache headers.
type WellKnown struct {
	discovery []byte
	jwks      []byte
}

type discoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

var registeredClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

// NewWellKnown renders the discovery document and JWKS for cfg.
func NewWellKnown(cfg Config) (*WellKnown, error) {
	claims := cfg.ClaimsSupported
	if len(claims) == 0 {
		claims = registeredClaims
	}
	doc := discoveryDoc{
		Issuer:                           cfg.Issuer,
		JWKSURI:                          cfg.JWKSURI,
		ResponseTypesSupported:           []string{"none"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid"},
		ClaimsSupported:                  claims,
	}
	discovery, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	jwks, err := cfg.Keys.JWKS()
	if err != nil {
		return nil, err
	}
	return &WellKnown{discovery: discovery, jwks: jwks}, nil
}

// Discovery serves GET /.well-known/openid-configuration.
func (wk *WellKnown) Discovery() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(wk.discovery)
	})
}

// JWKS serves the key set used to verify tokens. The cache window is short so
// validators pick up a rotated key promptly while still caching across the
// flood of verification traffic.
func (wk *WellKnown) JWKS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(wk.jwks)
	})
}
