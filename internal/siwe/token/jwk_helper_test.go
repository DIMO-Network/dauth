package token

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// parseFirstRSAJWK reconstructs an *rsa.PublicKey from the first key in a JWKS
// document, mirroring what a standard validator does when verifying a token.
func parseFirstRSAJWK(t *testing.T, jwksRaw []byte) *rsa.PublicKey {
	t.Helper()
	var set struct {
		Keys []struct {
			N string `json:"n"`
			E string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(jwksRaw, &set))
	require.NotEmpty(t, set.Keys)

	nBytes, err := base64.RawURLEncoding.DecodeString(set.Keys[0].N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(set.Keys[0].E)
	require.NoError(t, err)

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
}
