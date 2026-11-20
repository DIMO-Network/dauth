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
	t.Setenv("SIGNIN_ISSUER", "https://auth.dimo.zone")
	t.Setenv("PUBLIC_BASE_URL", "https://dauth.dimo.zone")
	t.Setenv("DIRECTORY_URL", "https://did.dimo.zone")
	t.Setenv("JWT_AUDIENCE", "dimo")
	t.Setenv("SIGNIN_SIGNING_KEY_1", "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----")
}

func TestLoad_Defaults(t *testing.T) {
	setMinimalEnv(t)
	s, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "https://auth.dimo.zone", s.Issuer)
	assert.Equal(t, "https://dauth.dimo.zone", s.PublicBaseURL)
	assert.Equal(t, "dauth.dimo.zone", s.Domain, "domain defaults to the public host")
	assert.Equal(t, []string{"dimo"}, s.Audience)
	assert.Equal(t, "https://did.dimo.zone", s.DirectoryURL)
	assert.Equal(t, 5*time.Minute, s.ChallengeTTL)
	assert.Equal(t, 15*time.Minute, s.TokenTTL)
	assert.Equal(t, 5*time.Minute, s.ApproveTTL)
	assert.Len(t, s.SigningKeys, 1)
}

func TestLoad_TrimsTrailingSlashIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_ISSUER", "https://auth.dimo.zone/")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "https://auth.dimo.zone", s.Issuer)
}

func TestLoad_RequiresIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_ISSUER", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SIGNIN_ISSUER")
}

func TestLoad_RejectsNonAbsoluteIssuer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_ISSUER", "auth.dimo.zone")
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
	t.Setenv("SIGNIN_SIGNING_KEY_1", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")
}

func TestLoad_NumberedSigningKeysInOrder(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_SIGNING_KEY_1", "key-one")
	t.Setenv("SIGNIN_SIGNING_KEY_2", "key-two")
	// A gap stops collection: KEY_4 is ignored because KEY_3 is absent.
	t.Setenv("SIGNIN_SIGNING_KEY_4", "key-four")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"key-one", "key-two"}, s.SigningKeys)
}

func TestLoad_RequiresDirectoryURL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("DIRECTORY_URL", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DIRECTORY_URL")
}

func TestLoad_MultipleAudiences(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("JWT_AUDIENCE", "dimo, https://din.dimo.zone")
	s, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"dimo", "https://din.dimo.zone"}, s.Audience)
}

func TestLoadRejectsBadTTLs(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"zero challenge":  {"CHALLENGE_TTL": "0s"},
		"negative token":  {"TOKEN_TTL": "-1m"},
		"zero approve":    {"APPROVE_TOKEN_TTL": "0s"},
		"approve > token": {"TOKEN_TTL": "1m", "APPROVE_TOKEN_TTL": "2m"},
	} {
		t.Run(name, func(t *testing.T) {
			setMinimalEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := Load()
			require.Error(t, err)
		})
	}
}

func TestLoadReadsCORSOrigins(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_CORS_ORIGINS", "https://login.dimo.org, https://console.dimo.org")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"https://login.dimo.org", "https://console.dimo.org"}, cfg.CORSOrigins)
}

func TestLoadApproveTTLDefaultFollowsShortTokenTTL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("TOKEN_TTL", "2m")
	cfg, err := Load()
	require.NoError(t, err, "setting only a short TOKEN_TTL must not break startup")
	assert.Equal(t, 2*time.Minute, cfg.ApproveTTL)

	t.Setenv("TOKEN_TTL", "1h")
	cfg, err = Load()
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, cfg.ApproveTTL, "the default stays 5m under a longer TOKEN_TTL")

	t.Setenv("TOKEN_TTL", "2m")
	t.Setenv("APPROVE_TOKEN_TTL", "3m")
	_, err = Load()
	require.Error(t, err, "an explicit APPROVE_TOKEN_TTL above TOKEN_TTL is still refused")
	assert.Contains(t, err.Error(), "APPROVE_TOKEN_TTL")
}

func TestLoadValidatesCORSOrigins(t *testing.T) {
	for _, ok := range []string{"https://login.dimo.org", "http://localhost:3000", "capacitor://localhost", "https://[::1]:8443"} {
		setMinimalEnv(t)
		t.Setenv("SIGNIN_CORS_ORIGINS", ok)
		_, err := Load()
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{
		"https://login.dimo.org/", "https://login.dimo.org/path", "https://Login.dimo.org", "HTTPS://login.dimo.org",
		"*", "https://*.dimo.org", "login.dimo.org", "https://login.dimo.org?x=1", "https://login.dimo.org#f",
		"https://user@login.dimo.org",
	} {
		setMinimalEnv(t)
		t.Setenv("SIGNIN_CORS_ORIGINS", "https://console.dimo.org,"+bad)
		_, err := Load()
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "SIGNIN_CORS_ORIGINS", bad)
		assert.Contains(t, err.Error(), bad)
	}
}

func TestLoadRejectsTrailingSlashAudience(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_ALLOWED_AUDIENCES", "https://accounts.dimo.org,https://other.dimo.org/")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SIGNIN_ALLOWED_AUDIENCES")
	assert.Contains(t, err.Error(), "https://other.dimo.org/")

	t.Setenv("SIGNIN_ALLOWED_AUDIENCES", "https://accounts.dimo.org,https://other.dimo.org")
	_, err = Load()
	assert.NoError(t, err)
}

func TestLoadRateLimit(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, 5, cfg.RateLimitPerSecond, "default")

	t.Setenv("SIGNIN_RATE_LIMIT_PER_SECOND", "0")
	cfg, err = Load()
	require.NoError(t, err)
	assert.Zero(t, cfg.RateLimitPerSecond, "0 disables")

	for _, bad := range []string{"-1", "five", "2.5"} {
		t.Setenv("SIGNIN_RATE_LIMIT_PER_SECOND", bad)
		_, err = Load()
		assert.Error(t, err, bad)
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("SIGNIN_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.7, fd00::/8, 172.16.5.9/12")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.1.7/32", "fd00::/8", "172.16.0.0/12"}, func() []string {
		var out []string
		for _, p := range cfg.TrustedProxies {
			out = append(out, p.String())
		}
		return out
	}())

	t.Setenv("SIGNIN_TRUSTED_PROXIES", "10.0.0.0/8,not-an-ip")
	_, err = Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-an-ip")
}
