// Package config loads the permission surface's runtime configuration from the
// environment, following dauth/din conventions: pure env vars, defaults applied
// here, and fail-fast validation so a misconfigured deployment never starts.
// Signing keys come from EXCHANGE_SIGNING_KEY_1, EXCHANGE_SIGNING_KEY_2,
// ... (see SigningKeys); the chart injects everything via envFrom.
package config

import (
	"fmt"
	"os"

	"github.com/DIMO-Network/dauth/internal/envx"
	"github.com/ethereum/go-ethereum/common"
)

// Settings is the full runtime configuration.
type Settings struct {
	Environment string
	LogLevel    string
	ServiceName string

	GRPCPort    int
	EnablePprof bool

	// Issuer is the iss claim stamped on minted permission tokens (e.g.
	// https://dauth.dimo.zone/exchange). It is namespaced (EXCHANGE_ISSUER)
	// because the merged binary's sign-in surface has its own distinct issuer.
	// TokenExpiration is the permission-token lifetime.
	Issuer          string
	TokenExpiration string

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
		Environment:                 envx.String("ENVIRONMENT", "local"),
		LogLevel:                    envx.String("LOG_LEVEL", "info"),
		ServiceName:                 envx.String("SERVICE_NAME", "token-exchange-api"),
		EnablePprof:                 os.Getenv("ENABLE_PPROF") == "true",
		Issuer:                      os.Getenv("EXCHANGE_ISSUER"),
		TokenExpiration:             envx.String("TOKEN_EXPIRATION", "10m"),
		BlockchainNodeURL:           os.Getenv("BLOCKCHAIN_NODE_URL"),
		ContractAddressSacd:         common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_SACD")),
		ContractAddressTemplate:     common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_TEMPLATE")),
		ContractAddressManufacturer: common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_MANUFACTURER")),
		ContractAddressVehicle:      common.HexToAddress(os.Getenv("CONTRACT_ADDRESS_VEHICLE")),
		IdentityURL:                 os.Getenv("IDENTITY_URL"),
		IPFSBaseURL:                 os.Getenv("IPFS_BASE_URL"),
		IPFSTimeout:                 envx.String("IPFS_TIMEOUT", "30s"),
	}

	var err error
	if s.GRPCPort, err = envx.Int("GRPC_PORT", 8086); err != nil {
		return s, err
	}
	if s.DIMORegistryChainID, err = envx.Uint("DIMO_REGISTRY_CHAIN_ID", 137); err != nil {
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
		"EXCHANGE_ISSUER":     s.Issuer,
		"BLOCKCHAIN_NODE_URL": s.BlockchainNodeURL,
		"IDENTITY_URL":        s.IdentityURL,
		"IPFS_BASE_URL":       s.IPFSBaseURL,
	}
}

// SigningKeys reads the permission surface's RSA signing keys from the
// environment as EXCHANGE_SIGNING_KEY_1, EXCHANGE_SIGNING_KEY_2, ... in
// priority order (the first is the active signer; the rest stay in the JWKS for
// rotation overlap). These keys are independent of the sign-in surface's.
func SigningKeys() []string {
	return envx.Numbered("EXCHANGE_SIGNING_KEY_")
}
