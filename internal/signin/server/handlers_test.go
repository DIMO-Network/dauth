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
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/DIMO-Network/dauth/internal/signin/nonce"
	"github.com/DIMO-Network/dauth/internal/signin/token"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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
	keys   *keyset.KeySet
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
	return &testEnv{ts: ts, handlers: h, directory: directory, priv: priv, pub: &rsaKey.PublicKey, holder: holder, keys: ks}
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
	assert.False(t, isDID("did:dimo:a/b"))
	assert.False(t, isDID("did:dimo:a?b"))
	assert.False(t, isDID("did:dimo:a b"))
	assert.True(t, isDID("did:web:example.com%3A3000:u"))
	assert.True(t, isDID("did:dimo:"+strings.Repeat("a", 128-len("did:dimo:"))))
	assert.False(t, isDID("did:dimo:"+strings.Repeat("a", 200)))
}

func TestChallengeRejectsOversizeAndPathyDIDs(t *testing.T) {
	e := newTestEnv(t)
	for name, did := range map[string]string{
		"200 chars": "did:dimo:" + strings.Repeat("a", 191),
		"slash":     "did:dimo:a/b",
	} {
		t.Run(name, func(t *testing.T) {
			status, body := e.post(t, "/challenge", map[string]any{"did": did, "scope": "read", "jkt": e.holder.Thumbprint()})
			assert.Equal(t, http.StatusBadRequest, status, body)
		})
	}
}

func TestTokenRejectsOversizeDPoP(t *testing.T) {
	e := newTestEnv(t)
	_, n := e.challenge(t, testDID)
	status, body := e.postWith(t, "/token", strings.Repeat("a", 5*1024), map[string]any{"nonce": n, "signature": "x"})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, "invalid_dpop_proof", body["error"])
}

// The real DirectoryClient maps the directory's status codes: 410 and 4xx
// refuse the sign-in, 5xx asks the caller to retry.
func TestDirectoryStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dirStatus int
		want      int
		wantErr   string
	}{
		{"gone", http.StatusGone, http.StatusUnauthorized, "invalid_grant"},
		{"bad request", http.StatusBadRequest, http.StatusUnauthorized, "invalid_grant"},
		{"unavailable", http.StatusServiceUnavailable, http.StatusServiceUnavailable, "server_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", tc.dirStatus)
			}))
			t.Cleanup(dir.Close)
			e := newTestEnv(t)
			e.handlers.Verifier = &Verifier{Directory: &DirectoryClient{Client: client.New(dir.URL)}}
			msg, n := e.challenge(t, testDID)
			status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
			assert.Equal(t, tc.want, status, body)
			assert.Equal(t, tc.wantErr, body["error"])
		})
	}
}

func TestCORS(t *testing.T) {
	e := newTestEnv(t)
	wk, err := oidc.NewWellKnown(oidc.Config{Issuer: testIssuer, JWKSURI: testIssuer + "/keys", Keys: e.keys})
	require.NoError(t, err)
	ts := httptest.NewServer(NewHandler(Config{Handlers: e.handlers, WellKnown: wk, CORSOrigins: []string{"https://login.test"}}))
	t.Cleanup(ts.Close)

	preflight := func(origin string) *http.Response {
		req, err := http.NewRequest(http.MethodOptions, ts.URL+"/token", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("allowed origin", func(t *testing.T) {
		resp := preflight("https://login.test")
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "https://login.test", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, OPTIONS", resp.Header.Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, DPoP", resp.Header.Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "600", resp.Header.Get("Access-Control-Max-Age"))
		assert.Contains(t, resp.Header.Values("Vary"), "Origin")
	})
	t.Run("disallowed origin", func(t *testing.T) {
		resp := preflight("https://evil.test")
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Methods"))
	})
	t.Run("no config", func(t *testing.T) {
		resp, err := http.DefaultClient.Do(mustReq(t, http.MethodOptions, e.ts.URL+"/token", "https://login.test"))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

func mustReq(t *testing.T, method, url, origin string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	req.Header.Set("Origin", origin)
	return req
}

// signK1 makes the directory's r||s signature over SHA-256 of data with a
// secp256k1 key.
func signK1(t *testing.T, priv *secp256k1.PrivateKey, data string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(data))
	sig := dcrecdsa.Sign(priv, hash[:])
	r, s := sig.R(), sig.S()
	raw := make([]byte, 64)
	r.PutBytesUnchecked(raw[:32])
	s.PutBytesUnchecked(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

// publishK1 lists a fresh secp256k1 key as did's #fragment in the directory.
func (e *testEnv) publishK1(t *testing.T, did, fragment string) *secp256k1.PrivateKey {
	t.Helper()
	k1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	e.directory.docs[did] = append(e.directory.docs[did], VerificationMethod{
		ID: did + "#" + fragment, PublicKeyMultibase: didkey.FromSecp256k1(k1.PubKey()).Multibase(),
	})
	return k1
}

// A DID whose #wallet key is secp256k1 signs in with a P-256 DPoP key: the two
// keys are unrelated, and the token binds to the DPoP key only.
func TestTokenK1DIDWithP256DPoP(t *testing.T) {
	e := newTestEnv(t)
	const did = "did:dimo:k1member"
	k1 := e.publishK1(t, did, "wallet")

	msg, n := e.challenge(t, did)
	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, k1, msg), "key": "wallet"})
	require.Equal(t, http.StatusOK, status, body)

	var claims token.Claims
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).
		ParseWithClaims(body["token"].(string), &claims, func(*jwt.Token) (any, error) { return e.pub, nil })
	require.NoError(t, err)
	assert.Equal(t, did, claims.Subject)
	require.NotNil(t, claims.Cnf)
	assert.Equal(t, e.holder.Thumbprint(), claims.Cnf.JKT)
}

// The key is resolved at token time: one removed from the document after the
// challenge was issued no longer signs in.
func TestTokenRejectsKeyRemovedAfterChallenge(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	e.directory.docs[testDID] = []VerificationMethod{e.directory.docs[testDID][1]} // only #dimo_org remains

	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestTokenUsesWalletFragment(t *testing.T) {
	e := newTestEnv(t)
	const did = "did:dimo:walletmember"
	k1 := e.publishK1(t, did, "wallet")
	other := e.publishK1(t, did, "signing") // a different key under the default fragment

	msg, n := e.challenge(t, did)
	// Signed by the #wallet key but verified as the default #signing: refused.
	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, k1, msg)})
	assert.Equal(t, http.StatusUnauthorized, status, body)

	msg, n = e.challenge(t, did)
	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, k1, msg), "key": "wallet"})
	assert.Equal(t, http.StatusOK, status, body)

	msg, n = e.challenge(t, did)
	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, other, msg)})
	assert.Equal(t, http.StatusOK, status, body)
}
