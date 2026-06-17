// Package tokenclaims provides a custom JWT token for token-exchange.
package tokenclaims

import (
	"github.com/DIMO-Network/dauth/internal/tokenexchange/models"
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
)

// GlobalIdentifier is the global identifier that represents all strings.
const GlobalIdentifier = models.GlobalIdentifier

// CustomClaims is the custom claims for token-exchange related information.
type CustomClaims struct {
	// Asset is the asset DID of the asset that permissions are being requested for currently either did:erc721 or did:ethr
	Asset       string       `json:"asset"`
	Permissions []string     `json:"permissions"`
	CloudEvents *CloudEvents `json:"cloud_events"`

	// Deprecated: Use Asset instead.
	ContractAddress common.Address `json:"contract_address"`
	// Deprecated: Use Asset instead.
	TokenID string `json:"token_id"`
	// Deprecated: Use Permissions instead.
	PrivilegeIDs []privileges.Privilege `json:"privilege_ids"`
}

type CloudEvents struct {
	Events []Event `json:"events"`
}

type Event struct {
	EventType string   `json:"event_type"`
	Source    string   `json:"source"`
	IDs       []string `json:"ids"`
	Tags      []string `json:"tags"`
}

// Token is a JWT token created by token-exchange.
type Token struct {
	jwt.RegisteredClaims
	CustomClaims
}
