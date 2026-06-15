package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/nonce"
	"github.com/DIMO-Network/dauth/internal/signer"
	"github.com/DIMO-Network/dauth/internal/token"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEnv struct {
	ts       *httptest.Server
	handlers *Handlers
	priv     *ecdsa.PrivateKey
	addr     common.Address
	pub      *rsa.PublicKey
	issuer   string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	ks, err := keyset.Load([]string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	require.NoError(t, err)

	wallet, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(wallet.PublicKey)

	const issuer = "https://auth.test"
	h := &Handlers{
		Store:    nonce.NewMemory(context.Background(), 1000),
		Verifier: signer.New(nil, zerolog.Nop()), // EOA-only
		Issuer: token.NewIssuer(token.Config{
			Keys: ks, Issuer: issuer, Audience: []string{"dimo"}, TTL: 10 * time.Minute,
		}),
		Domain:       "auth.test",
		URI:          issuer,
		Statement:    "Sign in to DIMO.",
		ChainID:      137,
		ChallengeTTL: 5 * time.Minute,
		Log:          zerolog.Nop(),
	}
	wk, err := NewWellKnown(issuer, issuer+"/keys", ks)
	require.NoError(t, err)
	srv, err := NewAuthServer(AuthConfig{Handlers: h, WellKnown: wk, Logger: zerolog.Nop()})
	require.NoError(t, err)

	return &testEnv{
		ts:       httptest.NewServer(srv.Handler),
		handlers: h,
		priv:     wallet,
		addr:     addr,
		pub:      &rsaKey.PublicKey,
		issuer:   issuer,
	}
}

func (e *testEnv) post(t *testing.T, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(e.ts.URL+path, "application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	resp.Body.Close()
	return resp, decoded
}

func (e *testEnv) challenge(t *testing.T) (challenge, nonce string) {
	t.Helper()
	resp, body := e.post(t, "/auth/challenge", map[string]any{"address": e.addr.Hex()})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return body["challenge"].(string), body["nonce"].(string)
}

func (e *testEnv) sign(t *testing.T, msg string) string {
	t.Helper()
	sig, err := crypto.Sign(accounts.TextHash([]byte(msg)), e.priv)
	require.NoError(t, err)
	return hexutil.Encode(sig)
}

func TestFullFlow_Success(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()

	challenge, nonce := e.challenge(t)
	assert.Contains(t, challenge, e.addr.Hex())
	assert.Contains(t, challenge, "Nonce: "+nonce)

	resp, body := e.post(t, "/auth/token", map[string]any{"nonce": nonce, "signature": e.sign(t, challenge)})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokenStr, _ := body["token"].(string)
	require.NotEmpty(t, tokenStr)
	assert.Equal(t, "Bearer", body["token_type"])

	// The issued token must validate against the published JWKS.
	var claims token.Claims
	parsed, err := jwt.NewParser(
		jwt.WithIssuer(e.issuer),
		jwt.WithAudience("dimo"),
		jwt.WithValidMethods([]string{"RS256"}),
	).ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) { return e.jwksPublicKey(t), nil })
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.Equal(t, e.addr.Hex(), claims.EthereumAddress)
	assert.Equal(t, e.addr.Hex(), claims.Subject)
}

func TestFullFlow_ReusedNonceRejected(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()

	challenge, nonce := e.challenge(t)
	sig := e.sign(t, challenge)

	resp, _ := e.post(t, "/auth/token", map[string]any{"nonce": nonce, "signature": sig})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Replaying the same nonce + signature must fail: the nonce is consumed.
	resp, body := e.post(t, "/auth/token", map[string]any{"nonce": nonce, "signature": sig})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestFullFlow_TamperedSignatureRejected(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()

	_, nonce := e.challenge(t)
	// Sign a different message than the stored challenge.
	resp, body := e.post(t, "/auth/token", map[string]any{"nonce": nonce, "signature": e.sign(t, "not the challenge")})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestChallenge_RejectsBadAddress(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()
	resp, body := e.post(t, "/auth/challenge", map[string]any{"address": "not-an-address"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_request", body["error"])
}

func TestToken_BadSignatureHexRejected(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()
	_, nonce := e.challenge(t)
	resp, body := e.post(t, "/auth/token", map[string]any{"nonce": nonce, "signature": "nothex"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_request", body["error"])
}

func TestExpiredChallengeRejected(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()
	// Force the issued challenge to already be expired by setting the handler
	// clock into the past so ExpiresAt < real now.
	e.handlers.Now = func() time.Time { return time.Now().Add(-time.Hour) }

	challenge, nonce := e.challenge(t)
	resp, body := e.post(t, "/auth/token", map[string]any{"nonce": nonce, "signature": e.sign(t, challenge)})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestWrongMethodRejected(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()
	resp, err := http.Get(e.ts.URL + "/auth/challenge")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestDiscoveryAndJWKS(t *testing.T) {
	e := newTestEnv(t)
	defer e.ts.Close()

	resp, err := http.Get(e.ts.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	var disc map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&disc))
	resp.Body.Close()
	assert.Equal(t, e.issuer, disc["issuer"])
	assert.Equal(t, e.issuer+"/keys", disc["jwks_uri"])

	resp, err = http.Get(e.ts.URL + "/keys")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Contains(t, string(body), "\"kty\":\"RSA\"")
}

// jwksPublicKey fetches the server's JWKS and reconstructs the signing key's
// public half, validating tokens exactly as an external consumer would.
func (e *testEnv) jwksPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	resp, err := http.Get(e.ts.URL + "/keys")
	require.NoError(t, err)
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			N string `json:"n"`
			E string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	require.NotEmpty(t, set.Keys)
	nBytes, err := base64.RawURLEncoding.DecodeString(set.Keys[0].N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(set.Keys[0].E)
	require.NoError(t, err)
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
}
