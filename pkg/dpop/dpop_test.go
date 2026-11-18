package dpop

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	v := NewVerifier()
	v.Now = func() time.Time { return now.Add(10 * time.Second) }

	proof, err := key.Proof("POST", "https://dauth.test/exchange?x=1", "", now)
	require.NoError(t, err)
	jkt, err := v.Verify(proof, "POST", "https://DAUTH.test/exchange#frag", "")
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), jkt)

	_, err = v.Verify(proof, "POST", "https://dauth.test/exchange", "")
	assert.ErrorIs(t, err, ErrInvalid, "replay")

	proof, err = key.Proof("GET", "https://dq.test/query", "", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid, "wrong method")

	proof, err = key.Proof("POST", "https://dq.test/other", "", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid, "wrong URL")

	proof, err = key.Proof("POST", "https://dq.test/query", "", now.Add(-time.Hour))
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid, "stale")
}

func TestAccessTokenHash(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	now := time.Now()
	v := NewVerifier()

	proof, err := key.Proof("POST", "https://dq.test/query", "token-a", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "token-b")
	assert.ErrorIs(t, err, ErrInvalid, "ath for another token")

	proof, err = key.Proof("POST", "https://dq.test/query", "", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "token-a")
	assert.ErrorIs(t, err, ErrInvalid, "ath missing")

	proof, err = key.Proof("POST", "https://dq.test/query", "token-a", now)
	require.NoError(t, err)
	_, err = v.Verify(proof, "POST", "https://dq.test/query", "token-a")
	assert.NoError(t, err)
}

func TestThumbprintRFC7638(t *testing.T) {
	// The RSA example from RFC 7638 §3.1.
	jwk := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}
	jkt, err := Thumbprint(jwk)
	require.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", jkt)
}

func TestRejectsPrivateJWKAndWrongTyp(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	proof, err := key.Proof("POST", "https://dq.test/query", "", time.Now())
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(hdr, &header))
	header["typ"] = "JWT"
	raw, _ := json.Marshal(header)
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	_, err = NewVerifier().Verify(strings.Join(parts, "."), "POST", "https://dq.test/query", "")
	assert.ErrorIs(t, err, ErrInvalid)
}
