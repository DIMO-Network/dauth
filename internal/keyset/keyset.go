// Package keyset loads the RSA signing keys and publishes their public halves
// as a JWKS. The first key is the active signer; the remaining keys are kept in
// the JWKS so tokens signed by a just-rotated-out key still verify during the
// overlap window.
package keyset

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// minRSABits is the smallest modulus dauth will sign with. 2048 is the floor
// for RS256 in any serious deployment.
const minRSABits = 2048

type signingKey struct {
	kid  string
	priv *rsa.PrivateKey
}

// KeySet holds the ordered signing keys. all[0] is the active signer.
type KeySet struct {
	all []signingKey
}

// Load parses PEM-encoded RSA private keys (PKCS#1 or PKCS#8) in priority
// order. The first key signs new tokens; every key's public half is published
// in the JWKS. Each key's id is the RFC 7638 thumbprint of its public key, so
// the kid is stable and collision-free across deployments.
func Load(pems []string) (*KeySet, error) {
	if len(pems) == 0 {
		return nil, errors.New("no signing keys provided")
	}
	ks := &KeySet{}
	seen := map[string]bool{}
	for i, p := range pems {
		priv, err := parseRSAPrivateKey([]byte(p))
		if err != nil {
			return nil, fmt.Errorf("signing key %d: %w", i+1, err)
		}
		if bits := priv.N.BitLen(); bits < minRSABits {
			return nil, fmt.Errorf("signing key %d: RSA modulus %d bits is below the %d-bit minimum", i+1, bits, minRSABits)
		}
		kid := thumbprint(&priv.PublicKey)
		if seen[kid] {
			return nil, fmt.Errorf("signing key %d: duplicate key (same thumbprint %s)", i+1, kid)
		}
		seen[kid] = true
		ks.all = append(ks.all, signingKey{kid: kid, priv: priv})
	}
	return ks, nil
}

// Sign returns claims as an RS256 JWT signed by the active key, with the active
// key's id in the kid header so validators select the right JWKS entry.
func (k *KeySet) Sign(claims jwt.Claims) (string, error) {
	active := k.all[0]
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = active.kid
	return tok.SignedString(active.priv)
}

// ActiveKID returns the id of the key currently signing tokens.
func (k *KeySet) ActiveKID() string { return k.all[0].kid }

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid PKCS#1 or PKCS#8 RSA key: %w", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, not RSA", keyAny)
	}
	return rsaKey, nil
}
