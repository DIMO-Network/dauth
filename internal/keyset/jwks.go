package keyset

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// jwk is an RFC 7517 JSON Web Key for an RSA public key used to verify
// signatures.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// JWKS returns the JSON Web Key Set (RFC 7517) containing the public half of
// every loaded key, suitable for serving at the jwks_uri. Standard validators
// (e.g. MicahParks/keyfunc, used by din) consume this directly.
func (k *KeySet) JWKS() ([]byte, error) {
	set := jwkSet{Keys: make([]jwk, 0, len(k.all))}
	for _, sk := range k.all {
		set.Keys = append(set.Keys, publicJWK(sk.kid, &sk.priv.PublicKey))
	}
	return json.Marshal(set)
}

func publicJWK(kid string, pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   b64(pub.N.Bytes()),
		E:   b64(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// thumbprint computes the RFC 7638 JWK thumbprint of an RSA public key: the
// base64url-encoded SHA-256 of the canonical JSON {"e":..,"kty":"RSA","n":..}
// with members in lexicographic order.
func thumbprint(pub *rsa.PublicKey) string {
	canonical := `{"e":"` + b64(big.NewInt(int64(pub.E)).Bytes()) +
		`","kty":"RSA","n":"` + b64(pub.N.Bytes()) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
