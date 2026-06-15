package keyset

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genPKCS8(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func genPKCS1(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestLoadAndSign_PKCS8(t *testing.T) {
	ks, err := Load([]string{genPKCS8(t, 2048)})
	require.NoError(t, err)

	signed, err := ks.Sign(jwt.RegisteredClaims{Subject: "0xabc"})
	require.NoError(t, err)

	// The token's kid header must be the active key id and resolve in the JWKS.
	tok, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, ks.ActiveKID(), tok.Header["kid"])
	assert.Equal(t, "RS256", tok.Header["alg"])
	assert.Contains(t, jwksKIDs(t, ks), ks.ActiveKID())
}

func TestLoad_PKCS1(t *testing.T) {
	ks, err := Load([]string{genPKCS1(t, 2048)})
	require.NoError(t, err)
	assert.NotEmpty(t, ks.ActiveKID())
}

func TestLoad_RejectsWeakKey(t *testing.T) {
	_, err := Load([]string{genPKCS8(t, 1024)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below")
}

func TestLoad_RejectsEmpty(t *testing.T) {
	_, err := Load(nil)
	require.Error(t, err)
}

func TestLoad_RejectsDuplicate(t *testing.T) {
	pemKey := genPKCS8(t, 2048)
	_, err := Load([]string{pemKey, pemKey})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestJWKS_PublishesAllKeysForRotation(t *testing.T) {
	active := genPKCS8(t, 2048)
	retiring := genPKCS8(t, 2048)
	ks, err := Load([]string{active, retiring})
	require.NoError(t, err)

	kids := jwksKIDs(t, ks)
	assert.Len(t, kids, 2, "both active and retiring keys must appear in the JWKS")
	assert.Equal(t, ks.ActiveKID(), kids[0], "the active key is published first")
}

func TestThumbprint_StableForSameKey(t *testing.T) {
	pemKey := genPKCS8(t, 2048)
	a, err := Load([]string{pemKey})
	require.NoError(t, err)
	b, err := Load([]string{pemKey})
	require.NoError(t, err)
	assert.Equal(t, a.ActiveKID(), b.ActiveKID(), "the kid is a deterministic thumbprint")
}

func jwksKIDs(t *testing.T, ks *KeySet) []string {
	t.Helper()
	raw, err := ks.JWKS()
	require.NoError(t, err)
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &set))
	kids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		assert.Equal(t, "RSA", k.Kty)
		assert.Equal(t, "RS256", k.Alg)
		assert.Equal(t, "sig", k.Use)
		assert.NotEmpty(t, k.N)
		assert.NotEmpty(t, k.E)
		kids = append(kids, k.Kid)
	}
	return kids
}
