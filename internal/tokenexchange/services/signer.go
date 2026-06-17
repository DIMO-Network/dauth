package services

import (
	"context"
	"fmt"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/services/access"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// PrivilegeTokenDTO is the input to minting a permission token: the validated
// access request plus the audience and subject to stamp on the output.
type PrivilegeTokenDTO struct {
	*access.AccessRequest
	Audience        []string
	ResponseSubject string
}

// TokenSigner mints token-exchange permission tokens, signing them locally with
// the service's own RSA keyset via the shared keyset package. It replaces the
// former DEX SignToken gRPC round-trip; the claim shape is intentionally
// identical, so downstream validators are unaffected.
type TokenSigner struct {
	keys   *keyset.KeySet
	issuer string
	ttl    time.Duration
	now    func() time.Time // injectable for tests
}

// NewTokenSigner builds a TokenSigner that stamps iss=issuer and exp=now+ttl,
// signing with the active key in keys.
func NewTokenSigner(keys *keyset.KeySet, issuer string, ttl time.Duration) *TokenSigner {
	return &TokenSigner{keys: keys, issuer: issuer, ttl: ttl, now: time.Now}
}

// SignPrivilegePayload builds the permission token from req and signs it. The
// custom-claim construction mirrors the previous DEX path exactly (including the
// deprecated contract_address/token_id/privilege_ids block) to keep the wire
// format byte-compatible for existing consumers.
func (s *TokenSigner) SignPrivilegePayload(_ context.Context, req PrivilegeTokenDTO) (string, error) {
	privs := make([]privileges.Privilege, len(req.Permissions))
	for i, perm := range req.Permissions {
		if permID, ok := tokenclaims.PrivilegeNameToID[perm]; ok {
			privs[i] = privileges.Privilege(permID)
		}
	}

	events := make([]tokenclaims.Event, len(req.EventFilters))
	for i, event := range req.EventFilters {
		events[i] = tokenclaims.Event{
			EventType: event.EventType,
			Source:    event.Source,
			IDs:       event.IDs,
			Tags:      event.Tags,
		}
	}

	now := s.now().UTC()
	tok := tokenclaims.Token{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   req.ResponseSubject,
			Audience:  jwt.ClaimStrings(req.Audience),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			ID:        uuid.NewString(),
		},
		CustomClaims: tokenclaims.CustomClaims{
			Asset:       req.Asset.String(),
			Permissions: req.Permissions,
			CloudEvents: &tokenclaims.CloudEvents{Events: events},

			// Deprecated fields, retained until downstream services migrate.
			ContractAddress: req.Asset.GetContractAddress(),
			TokenID:         req.Asset.GetTokenID().String(),
			PrivilegeIDs:    privs,
		},
	}

	signed, err := s.keys.Sign(tok)
	if err != nil {
		return "", fmt.Errorf("failed to sign permission token: %w", err)
	}
	return signed, nil
}
