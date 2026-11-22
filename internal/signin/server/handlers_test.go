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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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
	// resolves counts VerificationMethods calls.
	resolves atomic.Int32
	// rotation is each DID head's rotation keys (did:key strings); headErr,
	// when set, is what reading a head fails with.
	rotation map[string][]string
	headErr  error
	heads    atomic.Int32
}

// Both lookups fail on a cancelled context the way DirectoryClient does: the
// HTTP call fails, which is ErrDirectory.

func (d *fakeDirectory) RotationKeys(ctx context.Context, did string) ([]string, error) {
	d.heads.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDirectory, err)
	}
	if d.headErr != nil {
		return nil, d.headErr
	}
	if _, ok := d.docs[did]; !ok {
		return nil, ErrDIDNotFound
	}
	return d.rotation[did], nil
}

func (d *fakeDirectory) VerificationMethods(ctx context.Context, did string) ([]VerificationMethod, error) {
	d.resolves.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDirectory, err)
	}
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

// tryPost is postWith without testing.T, for goroutines: it returns errors
// instead of failing the test.
func (e *testEnv) tryPost(path, proof string, body any) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if proof != "" {
		req.Header.Set(dpop.HeaderName, proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, err
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
	e.setRotationKeys(testDID, didKeyOf(t, e.priv)) // #signing is the root, as on an org
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
	assert.True(t, isDID("did:web:example.com%3a3000"))
	assert.False(t, isDID("did:dimo:a%"))
	assert.False(t, isDID("did:dimo:a%3"))
	assert.False(t, isDID("did:dimo:a%zz"))
	assert.False(t, isDID("did:dimo:%"))
	assert.True(t, isDID("did:dimo:a:b"))
	assert.True(t, isDID("did:web:example.com%3A"))
	assert.False(t, isDID("did:dimo:a:"), "a method-specific id may not end in ':'")
	assert.False(t, isDID("did:dimo::"))
	assert.False(t, isDID("did:web:example.com:"))
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

// The real DirectoryClient maps the directory's status codes: 404, 400, 410
// and 422 refuse the sign-in; 408, 429, other 4xx and 5xx ask the caller to
// retry.
func TestDirectoryStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dirStatus int
		want      int
		wantErr   string
	}{
		{"not found", http.StatusNotFound, http.StatusUnauthorized, "invalid_grant"},
		{"gone", http.StatusGone, http.StatusUnauthorized, "invalid_grant"},
		{"bad request", http.StatusBadRequest, http.StatusUnauthorized, "invalid_grant"},
		{"unprocessable", http.StatusUnprocessableEntity, http.StatusUnauthorized, "invalid_grant"},
		{"request timeout", http.StatusRequestTimeout, http.StatusServiceUnavailable, "server_error"},
		{"too many requests", http.StatusTooManyRequests, http.StatusServiceUnavailable, "server_error"},
		{"forbidden", http.StatusForbidden, http.StatusServiceUnavailable, "server_error"},
		{"internal error", http.StatusInternalServerError, http.StatusServiceUnavailable, "server_error"},
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
		assert.Empty(t, resp.Header.Values("Vary"))
	})
	// With origins configured, every response varies on Origin, so a shared
	// cache never hands one origin's answer (or a no-Origin answer) to another.
	t.Run("vary without origin", func(t *testing.T) {
		for _, path := range []string{"/keys", "/.well-known/openid-configuration", "/nope"} {
			resp, err := http.Get(ts.URL + path)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Contains(t, resp.Header.Values("Vary"), "Origin", path)
			assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), path)
		}
		status, header := postTo(t, ts.URL+"/challenge", map[string]any{"did": "nope"})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, header.Values("Vary"), "Origin", "POST /challenge")
	})
	t.Run("vary with disallowed origin", func(t *testing.T) {
		resp, err := http.DefaultClient.Do(mustReq(t, http.MethodGet, ts.URL+"/keys", "https://evil.test"))
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Contains(t, resp.Header.Values("Vary"), "Origin")
	})
}

// A browser reads Retry-After only when the response exposes it, so a real
// response to an allowed origin does, a retryable 503 here. Any other origin
// gets no CORS headers at all.
func TestCORSExposesRetryAfter(t *testing.T) {
	e := newTestEnv(t)
	wk, err := oidc.NewWellKnown(oidc.Config{Issuer: testIssuer, JWKSURI: testIssuer + "/keys", Keys: e.keys})
	require.NoError(t, err)
	ts := httptest.NewServer(NewHandler(Config{Handlers: e.handlers, WellKnown: wk, CORSOrigins: []string{"https://login.test"}}))
	t.Cleanup(ts.Close)
	msg, n := e.challenge(t, testDID)
	raw, err := json.Marshal(map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.NoError(t, err)
	e.handlers.DPoP = failingDPoP{err: errors.New("DPoP replay cache full")}

	unavailable := func(origin string) *http.Response {
		proof, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", bytes.NewReader(raw))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(dpop.HeaderName, proof)
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, origin)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"), origin)
		return resp
	}

	resp := unavailable("https://login.test")
	assert.Equal(t, "https://login.test", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Retry-After", resp.Header.Get("Access-Control-Expose-Headers"))

	resp = unavailable("https://evil.test")
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
		assert.Empty(t, resp.Header.Get(h), h)
	}
	assert.Contains(t, resp.Header.Values("Vary"), "Origin")
}

// postTo posts body as JSON to url and returns the status and headers.
func postTo(t *testing.T, url string, body any) (int, http.Header) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header
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

// countingDPoP counts the proofs it is asked to verify.
type countingDPoP struct {
	inner ProofVerifier
	mu    sync.Mutex
	calls int
}

func (c *countingDPoP) Verify(proof, method, requestURL, accessToken string) (string, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.inner.Verify(proof, method, requestURL, accessToken)
}

func (c *countingDPoP) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// An unknown nonce is refused before the proof is verified, so its jti is
// never recorded: the same proof still works for a real challenge.
func TestTokenUnknownNonceSkipsProofVerification(t *testing.T) {
	e := newTestEnv(t)
	counter := &countingDPoP{inner: e.handlers.DPoP}
	e.handlers.DPoP = counter

	proof, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
	require.NoError(t, err)
	status, body := e.postWith(t, "/token", proof, map[string]any{"nonce": "never-issued", "signature": "x"})
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Zero(t, counter.count(), "an unknown nonce must not reach DPoP verification")

	msg, n := e.challenge(t, testDID)
	status, body = e.postWith(t, "/token", proof, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	assert.Equal(t, http.StatusOK, status, body, "the proof's jti must not have been recorded")
	assert.Equal(t, 1, counter.count())
}

// A proof from another key is refused without spending the challenge, so
// whoever has only the nonce cannot burn it.
func TestTokenWrongKeyLeavesChallenge(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	other, err := dpop.GenerateKey()
	require.NoError(t, err)

	status, body := e.redeem(t, other, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, "invalid_dpop_proof", body["error"])

	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	assert.Equal(t, http.StatusOK, status, body, "the right key must still redeem the challenge")
}

// A directory that does not answer is a 503 that spends nothing: the client
// retries /token with the same nonce and signature and a fresh proof, without
// signing again.
func TestTokenDirectoryOutageLeavesChallenge(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	req := map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)}

	e.directory.err = fmt.Errorf("%w: connection refused", ErrDirectory)
	status, body := e.redeem(t, e.holder, req)
	require.Equal(t, http.StatusServiceUnavailable, status, body)
	assert.Equal(t, "server_error", body["error"])
	_, err := e.handlers.Store.Peek(context.Background(), n)
	require.NoError(t, err, "a directory outage must not spend the challenge")

	e.directory.err = nil
	status, body = e.redeem(t, e.holder, req)
	require.Equal(t, http.StatusOK, status, body, "the retry with a fresh proof must redeem the challenge")
	assert.Equal(t, "DPoP", body["token_type"])

	status, body = e.redeem(t, e.holder, req)
	assert.Equal(t, http.StatusUnauthorized, status, body)
	assert.Equal(t, "invalid_grant", body["error"], "a redeemed challenge is spent")
}

// R5-F7: a failed attempt from the challenge's own key spends the challenge.
// A request that holds the named key but brings a bad signature, an unknown
// or forbidden key, or a DID the directory does not hold is refused and the
// challenge is consumed, so the right signature cannot redeem it afterwards:
// one challenge buys one verified proof and one directory resolve, not one per
// attempt.
func TestTokenFailedAttemptSpendsChallenge(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		did  string
		// failing is the refused /token body for the challenge msg with nonce n.
		failing func(e *testEnv, msg, n string) map[string]any
	}{
		{"another key's signature", testDID, func(_ *testEnv, msg, n string) map[string]any {
			return map[string]any{"nonce": n, "signature": sign(t, other, msg)}
		}},
		{"signature over another message", testDID, func(e *testEnv, msg, n string) map[string]any {
			return map[string]any{"nonce": n, "signature": sign(t, e.priv, msg+" ")}
		}},
		{"unknown verification method", testDID, func(e *testEnv, msg, n string) map[string]any {
			return map[string]any{"nonce": n, "signature": sign(t, e.priv, msg), "key": "other"}
		}},
		{"the org commit key", testDID, func(e *testEnv, msg, n string) map[string]any {
			return map[string]any{"nonce": n, "signature": sign(t, e.priv, msg), "key": "dimo_org"}
		}},
		{"a DID the directory does not hold", "did:dimo:nobody", func(e *testEnv, msg, n string) map[string]any {
			return map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			msg, n := e.challenge(t, tc.did)
			status, body := e.redeem(t, e.holder, tc.failing(e, msg, n))
			require.Equal(t, http.StatusUnauthorized, status, body)
			require.Equal(t, "invalid_grant", body["error"])
			_, err := e.handlers.Store.Peek(context.Background(), n)
			require.ErrorIs(t, err, nonce.ErrNotFound, "a failed attempt spends the challenge")

			status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
			assert.Equal(t, http.StatusUnauthorized, status, body)
			assert.Equal(t, "invalid_grant", body["error"], "the right signature cannot redeem a spent challenge")
		})
	}
}

// Repeated bad signatures on one challenge cost one directory resolve: the
// first spends the challenge, and the rest stop at the store.
func TestTokenBadSignaturesResolveOnce(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for range 5 {
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, other, msg)})
		require.Equal(t, http.StatusUnauthorized, status, body)
	}
	assert.EqualValues(t, 1, e.directory.resolves.Load())
}

// failingDPoP refuses every proof with err.
type failingDPoP struct{ err error }

func (f failingDPoP) Verify(string, string, string, string) (string, error) { return "", f.err }

// A DPoP error that does not wrap dpop.ErrInvalid means the proof could not be
// checked (a full replay cache, once did-directory's ErrReplayCacheFull
// arrives), not that it is bad: 503 with Retry-After, and the challenge is left
// for the retry. An ErrInvalid failure is still 400 invalid_dpop_proof.
func TestTokenUncheckableProofIs503(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	req := map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)}

	e.handlers.DPoP = failingDPoP{err: errors.New("DPoP replay cache full")}
	proof, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
	require.NoError(t, err)
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	httpReq, err := http.NewRequest(http.MethodPost, e.ts.URL+"/token", bytes.NewReader(raw))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(dpop.HeaderName, proof)
	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, body)
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	assert.Equal(t, "server_error", body["error"])
	_, err = e.handlers.Store.Peek(context.Background(), n)
	require.NoError(t, err, "a proof that could not be checked must not spend the challenge")

	e.handlers.DPoP = failingDPoP{err: fmt.Errorf("%w: proof replayed", dpop.ErrInvalid)}
	status, out := e.redeem(t, e.holder, req)
	assert.Equal(t, http.StatusBadRequest, status, out)
	assert.Equal(t, "invalid_dpop_proof", out["error"])

	e.handlers.DPoP = dpop.NewVerifier()
	status, out = e.redeem(t, e.holder, req)
	assert.Equal(t, http.StatusOK, status, out)
}

// downStore is a challenge store whose Put or Peek fails with err when set.
type downStore struct {
	nonce.Store
	putErr, peekErr error
}

func (s *downStore) Put(ctx context.Context, n string, ch nonce.Challenge) error {
	if s.putErr != nil {
		return s.putErr
	}
	return s.Store.Put(ctx, n, ch)
}

func (s *downStore) Peek(ctx context.Context, n string) (nonce.Challenge, error) {
	if s.peekErr != nil {
		return nonce.Challenge{}, s.peekErr
	}
	return s.Store.Peek(ctx, n)
}

// redeemResponse posts body to /token with a fresh proof from the holder and
// returns the response, for its headers.
func (e *testEnv) redeemResponse(t *testing.T, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	proof, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/token", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(dpop.HeaderName, proof)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp
}

// Every 503 /signin answers is retryable and says when: Retry-After: 1.
func TestUnavailableSaysRetryAfter(t *testing.T) {
	t.Run("challenge store down at /challenge", func(t *testing.T) {
		e := newTestEnv(t)
		e.handlers.Store = &downStore{Store: e.handlers.Store, putErr: errors.New("connection refused")}
		status, header := postTo(t, e.ts.URL+"/challenge", map[string]any{"did": testDID, "scope": "read", "jkt": e.holder.Thumbprint()})
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, "1", header.Get("Retry-After"))
	})
	t.Run("challenge store down at /token", func(t *testing.T) {
		e := newTestEnv(t)
		msg, n := e.challenge(t, testDID)
		e.handlers.Store = &downStore{Store: e.handlers.Store, peekErr: errors.New("connection refused")}
		resp := e.redeemResponse(t, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	})
	// The real directory client against a directory that answers 500.
	t.Run("directory down", func(t *testing.T) {
		dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "down", http.StatusInternalServerError)
		}))
		t.Cleanup(dir.Close)
		e := newTestEnv(t)
		e.handlers.Verifier = &Verifier{Directory: &DirectoryClient{Client: client.New(dir.URL)}}
		msg, n := e.challenge(t, testDID)
		resp := e.redeemResponse(t, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
		_, err := e.handlers.Store.Peek(context.Background(), n)
		require.NoError(t, err, "a directory outage must not spend the challenge")
	})
	// TestTokenUncheckableProofIs503 covers the DPoP proof that could not be
	// checked.
}

// Concurrent redemptions of one challenge, each with its own fresh proof from
// the right key: exactly one gets a token.
func TestTokenConcurrentRedeem(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	sig := sign(t, e.priv, msg)

	const racers = 8
	proofs := make([]string, racers)
	for i := range proofs {
		p, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
		require.NoError(t, err)
		proofs[i] = p
	}
	// The goroutines only send results back: require (t.FailNow) must run on
	// the test goroutine.
	type result struct {
		status int
		err    error
	}
	results := make(chan result, racers)
	start := make(chan struct{})
	for _, proof := range proofs {
		go func() {
			<-start
			status, err := e.tryPost("/token", proof, map[string]any{"nonce": n, "signature": sig})
			results <- result{status, err}
		}()
	}
	close(start)

	var ok, refused int
	for range racers {
		res := <-results
		require.NoError(t, res.err)
		switch res.status {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
			refused++
		default:
			t.Errorf("unexpected status %d", res.status)
		}
	}
	assert.Equal(t, 1, ok, "exactly one redemption must win")
	assert.Equal(t, racers-1, refused)
}

// The challenge stores the resolved audience, so the token carries exactly
// the aud the challenge text named even if the default changes before /token.
func TestChallengeStoresResolvedAudience(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	assert.Contains(t, msg, "\nFor: dimo\n")

	stored, err := e.handlers.Store.Peek(context.Background(), n)
	require.NoError(t, err)
	assert.Equal(t, []string{"dimo"}, stored.Audience)

	// A new default between challenge and token must not change the aud.
	e.handlers.Issuer = token.NewIssuer(token.Config{Keys: e.keys, Issuer: testIssuer, Audience: []string{"changed"}, TTL: 10 * time.Minute, ApproveTTL: 2 * time.Minute})
	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.Equal(t, http.StatusOK, status, body)
	var claims token.Claims
	_, err = jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).
		ParseWithClaims(body["token"].(string), &claims, func(*jwt.Token) (any, error) { return e.pub, nil })
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"dimo"}, claims.Audience)
}

func TestChallengeAudienceRules(t *testing.T) {
	e := newTestEnv(t)
	many := make([]string, maxAudiences+1)
	for i := range many {
		many[i] = fmt.Sprintf("aud-%d", i)
	}
	e.handlers.AllowedAudiences = append([]string{"a", "b"}, many...)
	req := func(aud []string) (int, map[string]any) {
		return e.post(t, "/challenge", map[string]any{"did": testDID, "audience": aud, "scope": "read", "jkt": e.holder.Thumbprint()})
	}

	status, body := req([]string{"a", "b", "a"})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, "invalid_request", body["error"])

	status, body = req(many)
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, "invalid_request", body["error"])

	status, body = req(many[:maxAudiences])
	assert.Equal(t, http.StatusOK, status, body, "exactly the cap is allowed")

	// The order sent is the order signed and stamped: never sorted or deduped.
	status, body = req([]string{"b", "a"})
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body["challenge"], "\nFor: b, a\n")
	stored, err := e.handlers.Store.Peek(context.Background(), body["nonce"].(string))
	require.NoError(t, err)
	assert.Equal(t, []string{"b", "a"}, stored.Audience)
}

// rsaProof is a DPoP proof made with an RSA key, which dpop.Key cannot make.
func rsaProof(t *testing.T, key *rsa.PrivateKey, htu string) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"jti": fmt.Sprint(time.Now().UnixNano()), "htm": http.MethodPost, "htu": htu, "iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]any{
		"kty": "RSA", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}
	proof, err := tok.SignedString(key)
	require.NoError(t, err)
	return proof
}

// The thumbprint /token reads off a proof's header before verifying it is the
// jkt dpop.Verifier returns for the same proof, for EC and RSA keys.
func TestProofKeyThumbprintMatchesVerify(t *testing.T) {
	const htu = "https://auth.test/signin/token"
	v := dpop.NewVerifier()
	var proofs []string
	for range 5 {
		k, err := dpop.GenerateKey()
		require.NoError(t, err)
		p, err := k.Proof(http.MethodPost, htu, "", time.Now())
		require.NoError(t, err)
		proofs = append(proofs, p)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	proofs = append(proofs, rsaProof(t, rk, htu))

	for i, p := range proofs {
		claimed, err := proofKeyThumbprint(p)
		require.NoError(t, err, i)
		verified, err := v.Verify(p, http.MethodPost, htu, "")
		require.NoError(t, err, i)
		assert.Equal(t, verified, claimed, i)
	}

	for _, bad := range []string{"", "not-a-jwt", "a.b.c", strings.Repeat("x", 100)} {
		_, err := proofKeyThumbprint(bad)
		assert.Error(t, err, bad)
	}
}

// Wrong-key proofs never reach Verify, so they record no jti and spend
// nothing: 50 of them leave the challenge for the right key.
func TestTokenWrongKeyProofsNeverVerified(t *testing.T) {
	e := newTestEnv(t)
	counter := &countingDPoP{inner: e.handlers.DPoP}
	e.handlers.DPoP = counter
	msg, n := e.challenge(t, testDID)
	sig := sign(t, e.priv, msg)

	for i := range 50 {
		other, err := dpop.GenerateKey()
		require.NoError(t, err)
		status, body := e.redeem(t, other, map[string]any{"nonce": n, "signature": sig})
		require.Equal(t, http.StatusBadRequest, status, "proof %d: %v", i, body)
		require.Equal(t, "invalid_dpop_proof", body["error"], i)
	}
	// A header with no jwk at all is turned away the same way.
	status, body := e.postWith(t, "/token", "e30.e30.e30", map[string]any{"nonce": n, "signature": sig})
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, "invalid_dpop_proof", body["error"])
	assert.Zero(t, counter.count(), "no wrong-key proof may reach DPoP verification")

	_, err := e.handlers.Store.Peek(context.Background(), n)
	require.NoError(t, err, "the challenge must still be outstanding")

	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sig})
	assert.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, 1, counter.count(), "only the right key's proof is verified")
}

// The directory client applies isDID itself, so a DID from any caller (an
// /exchange client assertion's iss included) cannot reach the directory with
// a path in it.
func TestDirectoryClientRefusesInvalidDIDs(t *testing.T) {
	var hits atomic.Int32
	dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(dir.Close)
	dc := &DirectoryClient{Client: client.New(dir.URL)}

	for _, did := range []string{"did:dimo:../../admin", "did:dimo:a/../../health", "did:dimo:a?x=1", "did:dimo:a:", "did:"} {
		_, err := dc.VerificationMethods(context.Background(), did)
		assert.ErrorIs(t, err, ErrDIDUnusable, did)
	}
	assert.Zero(t, hits.Load(), "no invalid DID may reach the directory")

	_, err := dc.VerificationMethods(context.Background(), "did:dimo:valid")
	assert.ErrorIs(t, err, ErrDIDNotFound, "a valid DID is still resolved")
}

// limitedServer serves the surface with a rate limit of perSecond, trusting
// the loopback test client's X-Forwarded-For so each test can pose as any IP.
func (e *testEnv) limitedServer(t *testing.T, perSecond int) *httptest.Server {
	t.Helper()
	wk, err := oidc.NewWellKnown(oidc.Config{Issuer: testIssuer, JWKSURI: testIssuer + "/keys", Keys: e.keys})
	require.NoError(t, err)
	ts := httptest.NewServer(NewHandler(Config{
		Handlers: e.handlers, WellKnown: wk, CORSOrigins: []string{"https://login.test"},
		RateLimitPerSecond: perSecond, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")},
	}))
	t.Cleanup(ts.Close)
	return ts
}

// postAs posts body to url as client ip and returns the response.
func postAs(t *testing.T, url, ip string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Origin", "https://login.test")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return resp, out
}

func TestRateLimitPerIP(t *testing.T) {
	e := newTestEnv(t)
	// 1 a second, burst 2: three requests well inside a second hit the limit.
	ts := e.limitedServer(t, 1)
	challenge := map[string]any{"did": testDID, "scope": "read", "jkt": e.holder.Thumbprint()}

	for i := range 2 {
		resp, body := postAs(t, ts.URL+"/challenge", "203.0.113.1", challenge)
		require.Equal(t, http.StatusOK, resp.StatusCode, "request %d: %v", i, body)
	}
	resp, body := postAs(t, ts.URL+"/challenge", "203.0.113.1", challenge)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, body)
	assert.Equal(t, "rate_limited", body["error"])
	assert.NotEmpty(t, body["error_description"])
	assert.Equal(t, "1", resp.Header.Get("Retry-After"))
	assert.Equal(t, "https://login.test", resp.Header.Get("Access-Control-Allow-Origin"), "a browser can read the 429")
	assert.Equal(t, "Retry-After", resp.Header.Get("Access-Control-Expose-Headers"), "and its Retry-After")

	// /token shares the client's bucket.
	resp, body = postAs(t, ts.URL+"/token", "203.0.113.1", map[string]any{"nonce": "n", "signature": "s"})
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, body)

	// Another client is unaffected.
	resp, body = postAs(t, ts.URL+"/challenge", "203.0.113.2", challenge)
	assert.Equal(t, http.StatusOK, resp.StatusCode, body)

	// The read-only routes are never limited.
	for range 5 {
		r, err := http.Get(ts.URL + "/keys")
		require.NoError(t, err)
		_ = r.Body.Close()
		assert.Equal(t, http.StatusOK, r.StatusCode)
	}
}

func TestRateLimitZeroDisables(t *testing.T) {
	e := newTestEnv(t)
	ts := e.limitedServer(t, 0)
	challenge := map[string]any{"did": testDID, "scope": "read", "jkt": e.holder.Thumbprint()}
	for i := range 30 {
		resp, body := postAs(t, ts.URL+"/challenge", "203.0.113.1", challenge)
		require.Equal(t, http.StatusOK, resp.StatusCode, "request %d: %v", i, body)
	}
}

// IPv6 clients are limited per /64: addresses in one /64 share a bucket, and
// another /64 has its own.
func TestRateLimitIPv6PerSlash64(t *testing.T) {
	e := newTestEnv(t)
	ts := e.limitedServer(t, 1) // burst 2
	challenge := map[string]any{"did": testDID, "scope": "read", "jkt": e.holder.Thumbprint()}

	resp, body := postAs(t, ts.URL+"/challenge", "2001:db8:1:2::1", challenge)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	resp, body = postAs(t, ts.URL+"/challenge", "2001:db8:1:2::2", challenge)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	resp, body = postAs(t, ts.URL+"/challenge", "2001:db8:1:2:abcd::3", challenge)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "a third address in the same /64 shares the bucket: %v", body)

	resp, body = postAs(t, ts.URL+"/challenge", "2001:db8:1:3::1", challenge)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a different /64 has its own bucket: %v", body)
}

// R5-F1: the store budgets challenges per client address. One address asking
// for more than nonce.MaxPerClient challenges displaces only its own oldest;
// another address's challenge is untouched.
func TestChallengeBudgetIsPerClient(t *testing.T) {
	e := newTestEnv(t)
	ts := e.limitedServer(t, 0)
	req := map[string]any{"did": testDID, "scope": "read", "jkt": e.holder.Thumbprint()}
	ask := func(ip string) string {
		resp, body := postAs(t, ts.URL+"/challenge", ip, req)
		require.Equal(t, http.StatusOK, resp.StatusCode, body)
		return body["nonce"].(string)
	}
	outstanding := func(n string) bool {
		_, err := e.handlers.Store.Peek(context.Background(), n)
		return err == nil
	}

	other := ask("198.51.100.7")
	var flood []string
	for range nonce.MaxPerClient + 1 {
		flood = append(flood, ask("203.0.113.1"))
	}
	assert.False(t, outstanding(flood[0]), "the flooding address's oldest challenge is displaced")
	for _, n := range flood[1:] {
		assert.True(t, outstanding(n))
	}
	assert.True(t, outstanding(other), "another address's challenge is untouched")

	stored, err := e.handlers.Store.Peek(context.Background(), other)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.7", stored.Client)
}

// setRotationKeys makes keys the rotation keys of did's head.
func (e *testEnv) setRotationKeys(did string, keys ...string) {
	if e.directory.rotation == nil {
		e.directory.rotation = map[string][]string{}
	}
	e.directory.rotation[did] = keys
}

// didKeyOf is priv's public key as a did:key.
func didKeyOf(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	pub, err := didkey.FromECDSA(&priv.PublicKey)
	require.NoError(t, err)
	return pub.DIDKey()
}

// tokenClaims decodes an issued token's claims as JSON, checking its
// signature.
func (e *testEnv) tokenClaims(t *testing.T, tok string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).
		ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return e.pub, nil })
	require.NoError(t, err)
	return claims
}

// Contract 1: every token names the verification method that signed in, as
// its fragment without '#'.
func TestTokenNamesItsVerificationMethod(t *testing.T) {
	e := newTestEnv(t)
	msg, n := e.challenge(t, testDID)
	status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "signing", e.tokenClaims(t, body["token"].(string))["vm"], "the default key")

	const did = "did:dimo:k1member"
	k1 := e.publishK1(t, did, "wallet")
	msg, n = e.challenge(t, did)
	status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, k1, msg), "key": "#wallet"})
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "wallet", e.tokenClaims(t, body["token"].(string))["vm"], "named with or without '#', claimed without")
}

// Contract 1 (R5-F2): approve is issued only when the did:key of the
// verification method that signed in is also one of the DID head's rotation
// keys. Otherwise /signin/token answers 403 key_not_allowed, and the refused
// attempt spends the challenge.
func TestApproveNeedsRotationKey(t *testing.T) {
	t.Run("a device key signs in for read and write, not approve", func(t *testing.T) {
		e := newTestEnv(t)
		root, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		e.setRotationKeys(testDID, didKeyOf(t, root)) // #signing is not a rotation key

		msg, n := e.challengeFor(t, testDID, "read write")
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, "read write", body["scope"])
		assert.Zero(t, e.directory.heads.Load(), "only approve reads the head")

		msg, n = e.challengeFor(t, testDID, "read write approve")
		status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusForbidden, status, body)
		assert.Equal(t, "key_not_allowed", body["error"])
		assert.Equal(t, "approve needs a rotation key", body["error_description"])
		assert.Nil(t, body["token"])
		_, err = e.handlers.Store.Peek(context.Background(), n)
		assert.ErrorIs(t, err, nonce.ErrNotFound, "the refused attempt spends the challenge")
	})

	t.Run("a DID with no rotation keys gets no approve", func(t *testing.T) {
		e := newTestEnv(t)
		msg, n := e.challengeFor(t, testDID, "approve")
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		assert.Equal(t, http.StatusForbidden, status, body)
		assert.Equal(t, "key_not_allowed", body["error"])
	})

	t.Run("a person's #wallet, a rotation key, gets approve", func(t *testing.T) {
		e := newTestEnv(t)
		const did = "did:dimo:person"
		k1 := e.publishK1(t, did, "wallet")
		device := e.publishK1(t, did, "signing")
		e.setRotationKeys(did, didkey.FromSecp256k1(k1.PubKey()).DIDKey())

		msg, n := e.challengeFor(t, did, "read write approve")
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, k1, msg), "key": "wallet"})
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, "read write approve", body["scope"])
		assert.Equal(t, "wallet", e.tokenClaims(t, body["token"].(string))["vm"])

		msg, n = e.challengeFor(t, did, "approve")
		status, body = e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": signK1(t, device, msg)})
		assert.Equal(t, http.StatusForbidden, status, "the same person's device key: %v", body)
	})

	t.Run("an org's #signing, its root, gets approve", func(t *testing.T) {
		e := newTestEnv(t)
		e.setRotationKeys(testDID, didKeyOf(t, e.priv))
		msg, n := e.challengeFor(t, testDID, "read write approve")
		status, body := e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, "signing", e.tokenClaims(t, body["token"].(string))["vm"])
	})

	t.Run("a head that cannot be read is a 503 that spends nothing", func(t *testing.T) {
		e := newTestEnv(t)
		e.setRotationKeys(testDID, didKeyOf(t, e.priv))
		msg, n := e.challengeFor(t, testDID, "approve")
		req := map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)}

		e.directory.headErr = fmt.Errorf("%w: connection refused", ErrDirectory)
		resp := e.redeemResponse(t, req)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("Retry-After"))
		_, err := e.handlers.Store.Peek(context.Background(), n)
		require.NoError(t, err, "the challenge is kept for the retry")

		e.directory.headErr = nil
		status, body := e.redeem(t, e.holder, req)
		assert.Equal(t, http.StatusOK, status, body)
	})
}

// The real DirectoryClient reads rotation keys from the head the directory
// serves at GET /<did>/data, alongside the document at GET /<did>.
func TestApproveThroughDirectoryClient(t *testing.T) {
	e := newTestEnv(t)
	signing, err := didkey.FromECDSA(&e.priv.PublicKey)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	const org, member = "did:dimo:org", "did:dimo:member2"
	heads := map[string]string{
		org:    `{"did":"` + org + `","rotationKeys":["` + signing.DIDKey() + `"]}`,
		member: `{"did":"` + member + `","rotationKeys":["` + didKeyOf(t, other) + `"]}`,
	}
	var headStatus atomic.Int32
	headStatus.Store(http.StatusOK)
	dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		did, data := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/data")
		head, ok := heads[did]
		switch {
		case !ok:
			http.Error(w, `{"error":"DID not found"}`, http.StatusNotFound)
		case data && headStatus.Load() != http.StatusOK:
			http.Error(w, "down", int(headStatus.Load()))
		case data:
			_, _ = io.WriteString(w, head)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": did, "verificationMethod": []map[string]string{
				{"id": did + "#signing", "type": "Multikey", "controller": did, "publicKeyMultibase": signing.Multibase()},
			}})
		}
	}))
	t.Cleanup(dir.Close)
	e.handlers.Verifier = &Verifier{Directory: &DirectoryClient{Client: client.New(dir.URL)}}
	redeem := func(did string) (int, map[string]any) {
		msg, n := e.challengeFor(t, did, "read approve")
		return e.redeem(t, e.holder, map[string]any{"nonce": n, "signature": sign(t, e.priv, msg)})
	}

	status, body := redeem(org)
	assert.Equal(t, http.StatusOK, status, "the org's #signing is its root: %v", body)

	status, body = redeem(member)
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Equal(t, "key_not_allowed", body["error"])

	headStatus.Store(http.StatusInternalServerError)
	status, body = redeem(org)
	assert.Equal(t, http.StatusServiceUnavailable, status, body)
	assert.Equal(t, "server_error", body["error"])

	heads[org] = "not json"
	headStatus.Store(http.StatusOK)
	status, body = redeem(org)
	assert.Equal(t, http.StatusServiceUnavailable, status, body)

	_, err = (&DirectoryClient{Client: client.New(dir.URL)}).RotationKeys(context.Background(), "did:dimo:a/../x")
	assert.ErrorIs(t, err, ErrDIDUnusable, "an invalid DID never reaches the directory")
}

// ctxStore is a challenge store whose Consume fails on a cancelled context,
// as the Postgres store's does.
type ctxStore struct{ nonce.Store }

func (s ctxStore) Consume(ctx context.Context, n, jkt string) (nonce.Challenge, error) {
	if err := ctx.Err(); err != nil {
		return nonce.Challenge{}, fmt.Errorf("consuming challenge: %w", err)
	}
	return s.Store.Consume(ctx, n, jkt)
}

// cancelingDPoP verifies proofs with inner, then cancels the request: the
// client hangs up just after its proof has verified.
type cancelingDPoP struct {
	inner  ProofVerifier
	cancel context.CancelFunc
}

func (c cancelingDPoP) Verify(proof, method, requestURL, accessToken string) (string, error) {
	jkt, err := c.inner.Verify(proof, method, requestURL, accessToken)
	c.cancel()
	return jkt, err
}

// Once the proof has verified as the challenge's key, the attempt runs to
// completion whatever the client does: hanging up does not turn a refusal
// into a 503 that leaves the challenge for another try (R5-F7).
func TestTokenClientAbortStillSpends(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
		setup func(e *testEnv)
		sig   func(e *testEnv, msg string) string
		want  int
	}{
		{"bad signature", "read", func(*testEnv) {},
			func(e *testEnv, msg string) string { return sign(t, e.priv, msg+" ") }, http.StatusUnauthorized},
		{"approve without a rotation key", "approve",
			func(e *testEnv) { e.setRotationKeys(testDID) },
			func(e *testEnv, msg string) string { return sign(t, e.priv, msg) }, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			tc.setup(e)
			e.handlers.Store = ctxStore{Store: e.handlers.Store}
			msg, n := e.challengeFor(t, testDID, tc.scope)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e.handlers.DPoP = cancelingDPoP{inner: e.handlers.DPoP, cancel: cancel}
			raw, err := json.Marshal(map[string]any{"nonce": n, "signature": tc.sig(e, msg)})
			require.NoError(t, err)
			proof, err := e.holder.Proof(http.MethodPost, e.ts.URL+"/token", "", time.Now())
			require.NoError(t, err)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/token", bytes.NewReader(raw))
			req.Header.Set(dpop.HeaderName, proof)
			rec := httptest.NewRecorder()
			e.handlers.Token().ServeHTTP(rec, req)

			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
			_, err = e.handlers.Store.Peek(context.Background(), n)
			assert.ErrorIs(t, err, nonce.ErrNotFound, "the refused attempt spends the challenge")
		})
	}
}
