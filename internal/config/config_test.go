package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setMinimalEnv sets the required variables for a successful Load.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SIWE_ISSUER", "https://auth.dimo.zone")
	t.Setenv("PUBLIC_BASE_URL", "https://dauth.dimo.zone")
	t.Setenv("JWT_AUDIENCE", "dimo")
	t.Setenv("SIWE_SIGNING_KEY_1", "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----")
}

func TestLoad_Defaults(t *testing.T) {
	setMinimalEnv(t)
	s, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "https://auth.dimo.zone", s.Issuer)
	assert.Equal(t, "https://dauth.dimo.zone", s.PublicBaseURL)
	assert.Equal(t, "dauth.dimo.zone", s.Domain, "domain defaults to the public host")
	assert.Equal(t, []string{"dimo"}, s.Audience)
	assert.Equal(t, uint64(137), s.ChainID)
	assert.Equal(t, 5*time.Minute, s.ChallengeTTL)
	assert.Equal(t, time.Hour, s.TokenTTL)
	assert.Len(t, s.SigningKeys, 1)
}

func TestLoad_TrimsTrailingSlashIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIWE_ISSUER", "https://auth.dimo.zone/")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "https://auth.dimo.zone", s.Issuer)
}

func TestLoad_RequiresIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIWE_ISSUER", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SIWE_ISSUER")
}

func TestLoad_RejectsNonAbsoluteIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIWE_ISSUER", "auth.dimo.zone")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute URL")
}

func TestLoad_RequiresPublicBaseURL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("PUBLIC_BASE_URL", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PUBLIC_BASE_URL")
}

func TestLoad_RequiresAudience(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("JWT_AUDIENCE", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_AUDIENCE")
}

func TestLoad_RequiresSigningKey(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIWE_SIGNING_KEY_1", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")
}

func TestLoad_NumberedSigningKeysInOrder(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIWE_SIGNING_KEY_1", "key-one")
	t.Setenv("SIWE_SIGNING_KEY_2", "key-two")
	// A gap stops collection: KEY_4 is ignored because KEY_3 is absent.
	t.Setenv("SIWE_SIGNING_KEY_4", "key-four")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"key-one", "key-two"}, s.SigningKeys)
}

func TestLoad_ChainIDOverride(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CHAIN_ID", "80002")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, uint64(80002), s.ChainID)
}

func TestLoad_MultipleAudiences(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("JWT_AUDIENCE", "dimo, https://din.dimo.zone")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"dimo", "https://din.dimo.zone"}, s.Audience)
}
