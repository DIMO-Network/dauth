package server

import (
	"encoding/json"
	"net/http"

	"github.com/DIMO-Network/dauth/internal/keyset"
)

// WellKnown serves the standards-based validation surface: OIDC discovery and
// the JWKS. Both documents are static for the process lifetime (the key set is
// fixed at startup), so they are rendered once and served from memory with
// cache headers.
type WellKnown struct {
	discovery []byte
	jwks      []byte
}

// discoveryDoc is the subset of the OIDC discovery metadata dauth supports.
// dauth is not a full OAuth2 authorization server — it only issues tokens via
// the SIWE flow and publishes keys for validation — so the authorization and
// token endpoints are intentionally absent.
type discoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// NewWellKnown renders the discovery document and JWKS for the given issuer,
// jwks URI, and key set.
func NewWellKnown(issuer, jwksURI string, keys *keyset.KeySet) (*WellKnown, error) {
	doc := discoveryDoc{
		Issuer:                           issuer,
		JWKSURI:                          jwksURI,
		ResponseTypesSupported:           []string{"none"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid"},
		ClaimsSupported:                  []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "ethereum_address"},
	}
	discovery, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	jwks, err := keys.JWKS()
	if err != nil {
		return nil, err
	}
	return &WellKnown{discovery: discovery, jwks: jwks}, nil
}

// Discovery serves GET /.well-known/openid-configuration.
func (wk *WellKnown) Discovery() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(wk.discovery)
	})
}

// JWKS serves the key set used to verify tokens. The cache window is short so
// validators pick up a rotated key promptly while still caching across the
// flood of verification traffic.
func (wk *WellKnown) JWKS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(wk.jwks)
	})
}
