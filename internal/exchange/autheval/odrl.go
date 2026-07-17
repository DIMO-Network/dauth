package autheval

import (
	"fmt"
	"time"

	"github.com/DIMO-Network/dauth/internal/exchange/models"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
)

// odrlActions is the closed action vocabulary of DIMO ODRL profile v1: the
// existing permission names. An agreement granting any action outside this set
// is rejected outright rather than partially honored, so authoring typos fail
// loudly at exchange time instead of silently granting nothing.
var odrlActions = func() map[string]struct{} {
	actions := make(map[string]struct{})
	for name := range tokenclaims.PrivilegeNameToID {
		actions[name] = struct{}{}
	}
	for name := range tokenclaims.ManufacturerPrivilegeNameToID {
		actions[name] = struct{}{}
	}
	return actions
}()

// ODRLGrantMap evaluates a validated profile v1 agreement against the
// requested asset at the given instant and returns the granted permission
// names, each mapped to the constraint atoms it was granted under. A nil
// slice means the permission is unconditional.
func ODRLGrantMap(agreement *models.ODRLAgreement, assetDID models.AssetDID, now time.Time) (map[string][]tokenclaims.Constraint, error) {
	targetDID, err := models.DecodeAssetDID(agreement.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	if targetDID.String() != assetDID.String() {
		return nil, fmt.Errorf("target %s does not match requested asset %s", agreement.Target, assetDID.String())
	}
	if !agreement.SatisfiedAt(now) {
		return nil, fmt.Errorf("agreement is outside its validity period")
	}
	grants := make(map[string][]tokenclaims.Constraint, len(agreement.Permission))
	for _, perm := range agreement.Permission {
		if _, ok := odrlActions[perm.Action]; !ok {
			return nil, fmt.Errorf("unknown action %q", perm.Action)
		}
		grants[perm.Action] = perm.Constraint
	}
	return grants, nil
}

// EvaluateScopedPermissions checks each requested permission against a scoped
// grant map. It returns the requested permissions that were granted under
// constraints — in request order, constraints copied verbatim from the grant —
// and the requested permissions the grant does not cover at all. A requested
// permission granted unconditionally appears in neither list.
func EvaluateScopedPermissions(grants map[string][]tokenclaims.Constraint, requested []string) (scoped []tokenclaims.ScopedPermission, lacks []string) {
	for _, perm := range requested {
		constraints, ok := grants[perm]
		if !ok {
			lacks = append(lacks, perm)
			continue
		}
		if len(constraints) > 0 {
			scoped = append(scoped, tokenclaims.ScopedPermission{Name: perm, Constraint: constraints})
		}
	}
	return scoped, lacks
}
