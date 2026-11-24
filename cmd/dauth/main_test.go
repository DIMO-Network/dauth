package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DIMO-Network/dauth/internal/exchange"
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
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

// unsignedAssertion is a client assertion that passes every check before the
// app's keys are resolved; its signature is never reached.
func unsignedAssertion(t *testing.T, app, aud, jkt string) string {
	t.Helper()
	now := time.Now()
	b64 := func(v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return b64(map[string]string{"alg": "ES256", "kid": app + "#signing"}) + "." +
		b64(map[string]any{"iss": app, "sub": app, "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			"jti": fmt.Sprint(now.UnixNano()), "cnf": map[string]string{"jkt": jkt}}) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 64))
}

// /exchange resolves an app's client-assertion keys through the same
// directory client as /signin, and maps its answers the same way: a DID the
// directory does not hold or will never serve is an invalid client (401
// invalid_client), and a directory that did not answer (408, 429, 5xx) is
// ErrAssertionKeys, which the handler turns into a 503 to retry.
func TestAssertionDirectoryStatusMapping(t *testing.T) {
	const aud, jkt = "https://auth.test/exchange", "jkt"
	for _, tc := range []struct {
		status int
		retry  bool
	}{
		{http.StatusNotFound, false},
		{http.StatusBadRequest, false},
		{http.StatusGone, false},
		{http.StatusUnprocessableEntity, false},
		{http.StatusRequestTimeout, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusServiceUnavailable, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", tc.status)
			}))
			t.Cleanup(dir.Close)
			v := newAssertionVerifier(newDIDVerifier(dir.URL), aud)
			_, err := v.Verify(context.Background(), unsignedAssertion(t, "did:dimo:app", aud, jkt), jkt)
			if tc.retry {
				assert.ErrorIs(t, err, exchange.ErrAssertionKeys)
			} else {
				assert.ErrorIs(t, err, exchange.ErrInvalidAssertion)
				assert.NotErrorIs(t, err, exchange.ErrAssertionKeys)
			}
		})
	}
}

// An /exchange client assertion whose iss is a DID with a path in it passes
// the exchange's own loose DID check, but the shared directory client refuses
// it before any request: an invalid client, never a directory call.
func TestAssertionPathTraversalDIDNeverReachesDirectory(t *testing.T) {
	const aud, jkt = "https://auth.test/exchange", "jkt"
	var hits atomic.Int32
	dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(dir.Close)
	v := newAssertionVerifier(newDIDVerifier(dir.URL), aud)

	_, err := v.Verify(context.Background(), unsignedAssertion(t, "did:dimo:../../admin", aud, jkt), jkt)
	assert.ErrorIs(t, err, exchange.ErrInvalidAssertion)
	assert.NotErrorIs(t, err, exchange.ErrAssertionKeys)
	assert.Zero(t, hits.Load(), "the directory must not be called")
}

// R7-F2 / R3-F6: did-directory's default replay cap (1,000,000 entries, about
// 157 MiB) doesn't fit dauth's 256Mi pod next to the nonce store, so each
// surface's DPoP verifier gets a smaller cap.
func TestDPoPVerifierReplayCapFitsThePod(t *testing.T) {
	v := newDPoPVerifier()
	assert.Equal(t, dpopReplayEntries, v.MaxReplayEntries)
	assert.Less(t, dpopReplayEntries, dpop.DefaultMaxReplayEntries)
	// Two surfaces at roughly 160 bytes an entry stay under 64 MiB together.
	assert.LessOrEqual(t, 2*dpopReplayEntries*160, 64<<20)
}
