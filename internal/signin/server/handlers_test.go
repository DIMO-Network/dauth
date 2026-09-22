package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/DIMO-Network/dauth/internal/signin/nonce"
	"github.com/DIMO-Network/dauth/internal/signin/token"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDID    = "did:dimo:member1"
	testIssuer = "https://auth.test/signin"
)

// fakeDirectory holds the documents a test publishes.
type fakeDirectory struct {
	docs map[string][]VerificationMethod
	err  error
}

func (d *fakeDirectory) VerificationMethods(_ context.Context, did string) ([]VerificationMethod, error) {
	if d.err != nil {
		return nil, d.err
	}
	vms, ok := d.docs[did]
	if !ok {
		return nil, ErrDIDNotFound
	}
	return vms, nil
}

type testEnv struct {
	ts        *httptest.Server
	handlers  *Handlers
	directory *fakeDirectory
	priv      *ecdsa.PrivateKey
	pub       *rsa.PublicKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	ks, err := keyset.Load([]string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := didkey.FromECDSA(&priv.PublicKey)
	require.NoError(t, err)
	directory := &fakeDirectory{docs: map[string][]VerificationMethod{
		testDID: {
			{ID: testDID + "#signing", PublicKeyMultibase: pub.Multibase()},
			{ID: testDID + "#dimo_org", PublicKeyMultibase: pub.Multibase()},
		},
	}}

	h := &Handlers{
		Store:            nonce.NewMemory(context.Background(), 1000),
		Verifier:         &Verifier{Directory: directory},
		Issuer:           token.NewIssuer(token.Config{Keys: ks, Issuer: testIssuer, Audience: []string{"dimo"}, TTL: 10 * time.Minute}),
		Domain:           "auth.test",
		ChallengeTTL:     5 * time.Minute,
		AllowedAudiences: []string{"org-host"},
		Log:              zerolog.Nop(),
	}
	wk, err := oidc.NewWellKnown(oidc.Config{Issuer: testIssuer, JWKSURI: testIssuer + "/keys", Keys: ks})
	require.NoError(t, err)
	ts := httptest.NewServer(NewHandler(Config{Handlers: h, WellKnown: wk}))
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, handlers: h, directory: directory, priv: priv, pub: &rsaKey.PublicKey}
}

// sign makes the directory's r||s signature over SHA-256 of data.
func sign(t *testing.T, priv *ecdsa.PrivateKey, data string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

func (e *testEnv) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(e.ts.URL+path, "application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out), string(data))
	return resp.StatusCode, out
}

func (e *testEnv) challenge(t *testing.T, did string) (string, string) {
	t.Helper()
	status, body := e.post(t, "/challenge", map[string]any{"did": did})
	require.Equal(t, http.StatusOK, status, body)
	return body["challenge"].(string), body["nonce"].(string)
}

func TestSignIn(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	assert.Contains(t, msg, testDID)
	assert.Contains(t, msg, n)

	status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.EqualValues(t, 600, body["expires_in"])

	var claims token.Claims
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(testIssuer), jwt.WithAudience("dimo")).
		ParseWithClaims(body["token"].(string), &claims, func(*jwt.Token) (any, error) { return e.pub, nil })
	require.NoError(t, err)
	assert.Equal(t, testDID, claims.Subject)

	// The nonce is single-use.
	status, body = e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestSignInRefusals(t *testing.T) {
	e := newTestEnv(t)

	t.Run("bad DID", func(t *testing.T) {
		status, body := e.post(t, "/challenge", map[string]any{"did": "not a did"})
		assert.Equal(t, http.StatusBadRequest, status, body)
	})

	t.Run("wrong key", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		msg, n := e.challenge(t, testDID)
		status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, other, msg)})
		assert.Equal(t, http.StatusUnauthorized, status, body)
		assert.Equal(t, "invalid_grant", body["error"])
	})

	t.Run("signature over another message", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg+" ")})
		assert.Equal(t, http.StatusUnauthorized, status, body)
	})

	t.Run("unknown verification method", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg), "key": "other"})
		assert.Equal(t, http.StatusUnauthorized, status, body)
		assert.Contains(t, body["error_description"], "no such verification method")
	})

	t.Run("the org commit key is not a login key", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg), "key": "dimo_org"})
		assert.Equal(t, http.StatusUnauthorized, status, body)
	})

	t.Run("DID the directory does not hold", func(t *testing.T) {
		msg, n := e.challenge(t, "did:dimo:nobody")
		status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusUnauthorized, status, body)
		assert.Contains(t, body["error_description"], "DID not found")
	})

	t.Run("directory down", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		e.directory.err = fmt.Errorf("%w: connection refused", ErrDirectory)
		defer func() { e.directory.err = nil }()
		status, body := e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusServiceUnavailable, status, body)
	})

	t.Run("disallowed audience", func(t *testing.T) {
		status, body := e.post(t, "/challenge", map[string]any{"did": testDID, "audience": []string{"evil"}})
		assert.Equal(t, http.StatusBadRequest, status, body)
	})
}

func TestSignInAudienceOverride(t *testing.T) {
	e := newTestEnv(t)
	status, body := e.post(t, "/challenge", map[string]any{"did": testDID, "audience": []string{"org-host"}})
	require.Equal(t, http.StatusOK, status, body)
	msg, n := body["challenge"].(string), body["nonce"].(string)

	status, body = e.post(t, "/token", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.Equal(t, http.StatusOK, status, body)
	var claims token.Claims
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).
		ParseWithClaims(body["token"].(string), &claims, func(*jwt.Token) (any, error) { return e.pub, nil })
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"org-host"}, claims.Audience)
}

func TestJWKSServed(t *testing.T) {
	e := newTestEnv(t)
	resp, err := http.Get(e.ts.URL + "/keys")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "RSA", set.Keys[0]["kty"])
}

func TestIsDID(t *testing.T) {
	assert.True(t, isDID("did:dimo:abc"))
	assert.False(t, isDID("did:dimo:"))
	assert.False(t, isDID("did:"))
	assert.False(t, isDID("dimo:abc"))
	assert.False(t, isDID("did:dimo:abc#signing"))
}
