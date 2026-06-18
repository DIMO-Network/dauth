// Package config loads the token-exchange binary's runtime configuration from
// the environment, following dauth/din conventions: pure env vars, defaults
// applied here, and fail-fast validation so a misconfigured deployment never
// starts. Signing keys come from SIGNING_KEY_1, SIGNING_KEY_2, ... (see
// SigningKeys); the chart injects everything via envFrom.
package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

// Settings is the full runtime configuration.
type Settings struct {
	Environment string
	LogLevel    string
	ServiceName string

	Port        int
	MonPort     int
	GRPCPort    int
	EnablePprof bool

	// Issuer is the iss claim stamped on minted permission tokens (e.g.
	// https://auth-roles-rights.dimo.zone), and identifies the JWKS this service
	// publishes. TokenExpiration is the permission-token lifetime.
	Issuer          string
	TokenExpiration string

	// JWKKeySetURL is the JWKS used to validate the inbound dauth token.
	JWKKeySetURL string

	BlockchainNodeURL           string
	ContractAddressSacd         common.Address
	ContractAddressTemplate     common.Address
	ContractAddressManufacturer common.Address
	ContractAddressVehicle      common.Address
	IdentityURL                 string
	IPFSBaseURL                 string
	IPFSTimeout                 string
	DIMORegistryChainID         uint64
}

// Load reads Settings from the environment, applying defaults, and fails if a
// required value is missing or malformed.
func Load() (Settings, error) {
	s := Settings{
		Environment:                 env("ENVIRONMENT", "local"),
		LogLevel:                    env("LOG_LEVEL", "info"),
		ServiceName:                 env("SERVICE_NAME", "token-exchange-api"),
		EnablePprof:                 os.Getenv("ENABLE_PPROF") == "true",
		Issuer:                      os.Getenv("ISSUER"),
		TokenExpiration:             env("TOKEN_EXPIRATION", "10m"),
		JWKKeySetURL:                os.Getenv("JWT_KEY_SET_URL"),
		BlockchainNodeURL:           os.Getenv("BLOCKCHAIN_NODE_URL"),
		ContractAddressSacd:         common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_SACD")),
		ContractAddressTemplate:     common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_TEMPLATE")),
		ContractAddressManufacturer: common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_MANUFACTURER")),
		ContractAddressVehicle:      common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_VEHICLE")),
		IdentityURL:                 os.Getenv("IDENTITY_URL"),
		IPFSBaseURL:                 os.Getenv("IPFS_BASE_URL"),
		IPFSTimeout:                 env("IPFS_TIMEOUT", "30s"),
	}

	var err error
	if s.Port, err = envInt("PORT", 8080); err != nil {
		return s, err
	}
	if s.MonPort, err = envInt("MON_PORT", 8888); err != nil {
		return s, err
	}
	if s.GRPCPort, err = envInt("GRPC_PORT", 8086); err != nil {
		return s, err
	}
	if s.DIMORegistryChainID, err = envUint("DIMO_REGISTRY_CHAIN_ID", 137); err != nil {
		return s, err
	}

	for name, val := range required(s) {
		if val == "" {
			return s, fmt.Errorf("%s is required", name)
		}
	}
	return s, nil
}

// required lists the env values that must be set for the service to start.
func required(s Settings) map[string]string {
	return map[string]string{
		"ISSUER":              s.Issuer,
		"JWT_KEY_SET_URL":     s.JWKKeySetURL,
		"BLOCKCHAIN_NODE_URL": s.BlockchainNodeURL,
		"IDENTITY_URL":        s.IdentityURL,
		"IPFS_BASE_URL":       s.IPFSBaseURL,
	}
}

// SigningKeys reads the service's RSA signing keys from the environment as
// SIGNING_KEY_1, SIGNING_KEY_2, ... in priority order (the first is the active
// signer; the rest stay in the JWKS for rotation overlap). token-exchange's
// signing key is independent of dauth's.
func SigningKeys() []string {
	var out []string
	for i := 1; ; i++ {
		v := os.Getenv("SIGNING_KEY_" + strconv.Itoa(i))
		if v == "" {
			break
		}
		out = append(out, v)
	}
	return out
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return n, nil
}

func envUint(key string, def uint64) (uint64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return n, nil
}
