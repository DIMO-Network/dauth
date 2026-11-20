package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeySet(t *testing.T, pems ...string) *keyset.KeySet {
	t.Helper()
	ks, err := keyset.Load(pems)
	require.NoError(t, err)
	return ks
}

func newKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// A sign-in key reused by /exchange would erase the keyset boundary between
// the two surfaces, so startup refuses it, whether the shared key is active or
// retiring on either side.
func TestCheckKeysDistinct(t *testing.T) {
	shared, a, b := newKeyPEM(t), newKeyPEM(t), newKeyPEM(t)
	signin := testKeySet(t, a, shared)

	assert.NoError(t, checkKeysDistinct(signin, testKeySet(t, b)))
	assert.Error(t, checkKeysDistinct(signin, testKeySet(t, shared)), "shared active exchange key")
	assert.Error(t, checkKeysDistinct(signin, testKeySet(t, b, shared)), "shared retiring exchange key")
}
