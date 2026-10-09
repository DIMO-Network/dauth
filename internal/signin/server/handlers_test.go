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
	"github.com/DIMO-Network/did-directory/pkg/dpop"
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
	// holder is the DPoP key tokens are bound to.
	holder *dpop.Key
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
		Issuer:           token.NewIssuer(token.Config{Keys: ks, Issuer: testIssuer, Audience: []string{"dimo"}, TTL: 10 * time.Minute, ApproveTTL: 2 * time.Minute}),
		DPoP:             dpop.NewVerifier(),
		Domain:           "auth.test",
		ChallengeTTL:     5 * time.Minute,
		AllowedAudiences: []string{"org-host"},
		Log:              zerolog.Nop(),
	}
	wk, err := oidc.NewWellKnown(oidc.Config{Issuer: testIssuer, JWKSURI: testIssuer + "/keys", Keys: ks})
	require.NoError(t, err)
	ts := httptest.NewServer(NewHandler(Config{Handlers: h, WellKnown: wk}))
	t.Cleanup(ts.Close)
	h.TokenURL = ts.URL + "/token"
	holder, err := dpop.GenerateKey()
	require.NoError(t, err)
	return &testEnv{ts: ts, handlers: h, directory: directory, priv: priv, pub: &rsaKey.PublicKey, holder: holder}
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
	return e.postWith(t, path, "", body)
}

// redeem posts body to /token with a fresh proof from key.
func (e *testEnv) redeem(t *testing.T, key *dpop.Key, body any) (int, map[string]any) {
	t.Helper()
	proof, err := key.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
	require.NoError(t, err)
	return e.postWith(t, "/token", proof, body)
}

func (e *testEnv) postWith(t *testing.T, path, proof string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if proof != "" {
		req.Header.Set(dpop.HeaderName, proof)
	}
	resp, err := http.DefaultClient.Do(req)
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
	return e.challengeFor(t, did, "read")
}

func (e *testEnv) challengeFor(t *testing.T, did, scope string) (string, string) {
	t.Helper()
	status, body := e.post(t, "/challenge", map[string]any{"did": did, "scope": scope, "jkt": e.holder.Thumbprint()})
	require.Equal(t, http.StatusOK, status, body)
	return body["challenge"].(string), body["nonce"].(string)
}

func TestSignIn(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	assert.Contains(t, msg, testDID)
	assert.Contains(t, msg, n)
	assert.Contains(t, msg, "For: dimo\nScope: read\nKey: "+e.holder.Thumbprint(), "the DID signs for what the token allows and who holds it")

	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "DPoP", body["token_type"])
	assert.EqualValues(t, 600, body["expires_in"])
	assert.Equal(t, "read", body["scope"])

	var claims token.Claims
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(testIssuer), jwt.WithAudience("dimo")).
		ParseWithClaims(body["token"].(string), &claims, func(*jwt.Token) (any, error) { return e.pub, nil })
	require.NoError(t, err)
	assert.Equal(t, testDID, claims.Subject)
	assert.Equal(t, "read", claims.Scope)
	require.NotNil(t, claims.Cnf)
	assert.Equal(t, e.holder.Thumbprint(), claims.Cnf.JKT)

	// The nonce is single-use.
	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
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
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, other, msg)})
		assert.Equal(t, http.StatusUnauthorized, status, body)
		assert.Equal(t, "invalid_grant", body["error"])
	})

	t.Run("signature over another message", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg+" ")})
		assert.Equal(t, http.StatusUnauthorized, status, body)
	})

	t.Run("unknown verification method", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg), "key": "other"})
		assert.Equal(t, http.StatusUnauthorized, status, body)
		assert.Contains(t, body["error_description"], "no such verification method")
	})

	t.Run("the org commit key is not a login key", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg), "key": "dimo_org"})
		assert.Equal(t, http.StatusUnauthorized, status, body)
	})

	t.Run("DID the directory does not hold", func(t *testing.T) {
		msg, n := e.challenge(t, "did:dimo:nobody")
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusUnauthorized, status, body)
		assert.Contains(t, body["error_description"], "DID not found")
	})

	t.Run("directory down", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		e.directory.err = fmt.Errorf("%w: connection refused", ErrDirectory)
		defer func() { e.directory.err = nil }()
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusServiceUnavailable, status, body)
	})

	t.Run("disallowed audience", func(t *testing.T) {
		status, body := e.post(t, "/challenge", map[string]any{"did": testDID, "audience": []string{"evil"}, "scope": "read", "jkt": e.holder.Thumbprint()})
		assert.Equal(t, http.StatusBadRequest, status, body)
	})

	for name, req := range map[string]map[string]any{
		"no scope":      {"did": testDID, "jkt": e.holder.Thumbprint()},
		"unknown scope": {"did": testDID, "scope": "read admin", "jkt": e.holder.Thumbprint()},
		"scope twice":   {"did": testDID, "scope": "read read", "jkt": e.holder.Thumbprint()},
		"no key":        {"did": testDID, "scope": "read"},
		"not a jkt":     {"did": testDID, "scope": "read", "jkt": "abc"},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := e.post(t, "/challenge", req)
			assert.Equal(t, http.StatusBadRequest, status, body)
		})
	}

	t.Run("no proof, and the challenge survives it", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		status, body := e.postWith(t, "/token", "", map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
		status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusOK, status, body)
	})

	t.Run("proof from a key the challenge does not name", func(t *testing.T) {
		other, err := dpop.GenerateKey()
		require.NoError(t, err)
		msg, n := e.challenge(t, testDID)
		status, body := e.redeem(t, other, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
	})

	t.Run("proof for another URL", func(t *testing.T) {
		msg, n := e.challenge(t, testDID)
		proof, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/challenge", "", time.Now())
		require.NoError(t, err)
		status, body := e.postWith(t, "/token", proof, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusBadRequest, status, body)
	})
}

// TestSignInApproveIsShortLived: a token that may approve lives for the
// approve lifetime, whatever else it carries.
func TestSignInApproveIsShortLived(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challengeFor(t, testDID, "approve read")
	assert.Contains(t, msg, "Scope: read approve")
	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.Equal(t, http.StatusOK, status, body)
	assert.EqualValues(t, 120, body["expires_in"])
	assert.Equal(t, "read approve", body["scope"])
}

func TestSignInAudienceOverride(t *testing.T) {
	e := newTestEnv(t)
	status, body := e.post(t, "/challenge", map[string]any{"did": testDID, "audience": []string{"org-host"}, "scope": "read write", "jkt": e.holder.Thumbprint()})
	require.Equal(t, http.StatusOK, status, body)
	msg, n := body["challenge"].(string), body["nonce"].(string)

	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
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
