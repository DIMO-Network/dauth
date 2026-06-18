package config

import (
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

// Settings contains the application config
type Settings struct {
	Environment                 string         `yaml:"ENVIRONMENT"`
	Port                        int            `yaml:"PORT"`
	MonPort                     int            `yaml:"MON_PORT"`
	GRPCPort                    int            `yaml:"GRPC_PORT"`
	EnablePprof                 bool           `yaml:"ENABLE_PPROF"`
	LogLevel                    string         `yaml:"LOG_LEVEL"`
	ServiceName                 string         `yaml:"SERVICE_NAME"`
	JWKKeySetURL                string         `yaml:"JWT_KEY_SET_URL"`
	BlockchainNodeURL           string         `yaml:"BLOCKCHAIN_NODE_URL"`
	ContractAddressSacd         common.Address `yaml:"CONTRACT_ADDRESS_SACD"`
	ContractAddressTemplate     common.Address `yaml:"CONTRACT_ADDRESS_TEMPLATE"`
	ContractAddressManufacturer common.Address `yaml:"CONTRACT_ADDRESS_MANUFACTURER"`
	ContractAddressVehicle      common.Address `yaml:"CONTRACT_ADDRESS_VEHICLE"`
	IdentityURL                 string         `yaml:"IDENTITY_URL"`
	IPFSBaseURL                 string         `yaml:"IPFS_BASE_URL"`
	IPFSTimeout                 string         `yaml:"IPFS_TIMEOUT"`
	DIMORegistryChainID         uint64         `yaml:"DIMO_REGISTRY_CHAIN_ID"`

	// Issuer is the iss claim stamped on minted permission tokens (e.g.
	// https://auth-roles-rights.dimo.zone). Downstream validators that check
	// iss are configured with this same value.
	Issuer string `yaml:"ISSUER"`
	// TokenExpiration is how long a minted permission token is valid, as a Go
	// duration string (e.g. "10m"). NOTE: confirm this matches the lifetime DEX
	// issued before cutting over. Empty defaults to 10m.
	TokenExpiration string `yaml:"TOKEN_EXPIRATION"`
}

// SigningKeys reads the service's RSA signing keys from the environment as
// SIGNING_KEY_1, SIGNING_KEY_2, ... in priority order (the first is the active
// signer; the rest stay in the JWKS for rotation overlap). They are read from
// the environment rather than settings.yaml so the PEM material is injected and
// handled exactly like dauth's keys, and so token-exchange's signing key stays
// independent of dauth's.
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
