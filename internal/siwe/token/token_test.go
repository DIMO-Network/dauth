package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKeySet(t *testing.T) *keyset.KeySet {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	ks, err := keyset.Load([]string{pemStr})
	require.NoError(t, err)
	return ks
}

func TestIssueRoundTrip(t *testing.T) {
	ks := newTestKeySet(t)
	jwksRaw, err := ks.JWKS()
	require.NoError(t, err)

	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	iss := NewIssuer(Config{
		Keys:     ks,
		Issuer:   "https://auth.dimo.zone",
		Audience: []string{"dimo"},
		TTL:      10 * time.Minute,
		Now:      func() time.Time { return now },
	})

	addr := common.HexToAddress("0x07b584f6a7125491c991ca2a45ab9e641b1cee1b")
	signed, exp, err := iss.Issue(addr)
	require.NoError(t, err)
	assert.Equal(t, now.Add(10*time.Minute), exp)

	// Verify the signature against the published JWKS key and check claims.
	pub := firstJWKSPublicKey(t, jwksRaw)
	var claims Claims
	parsed, err := jwt.NewParser(
		jwt.WithIssuer("https://auth.dimo.zone"),
		jwt.WithAudience("dimo"),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) }),
	).ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) { return pub, nil })
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	assert.Equal(t, addr.Hex(), claims.Subject)
	assert.Equal(t, addr.Hex(), claims.EthereumAddress)
	assert.Equal(t, "https://auth.dimo.zone", claims.Issuer)
	assert.NotEmpty(t, claims.ID, "jti must be set")
	assert.Equal(t, now.Unix(), claims.IssuedAt.Unix())
	assert.Equal(t, now.Add(10*time.Minute).Unix(), claims.ExpiresAt.Unix())
}

func TestIssue_RejectedAfterExpiry(t *testing.T) {
	ks := newTestKeySet(t)
	jwksRaw, err := ks.JWKS()
	require.NoError(t, err)
	now := time.Now().UTC()
	iss := NewIssuer(Config{Keys: ks, Issuer: "iss", Audience: []string{"a"}, TTL: time.Minute, Now: func() time.Time { return now }})
	signed, _, err := iss.Issue(common.HexToAddress("0x01"))
	require.NoError(t, err)

	pub := firstJWKSPublicKey(t, jwksRaw)
	_, err = jwt.NewParser(jwt.WithTimeFunc(func() time.Time { return now.Add(2 * time.Minute) })).
		Parse(signed, func(*jwt.Token) (any, error) { return pub, nil })
	require.Error(t, err, "an expired token must fail validation")
}

// firstJWKSPublicKey reconstructs an *rsa.PublicKey from the first JWKS entry so
// the test verifies tokens exactly as an external validator would.
func firstJWKSPublicKey(t *testing.T, jwksRaw []byte) *rsa.PublicKey {
	t.Helper()
	return parseFirstRSAJWK(t, jwksRaw)
}
