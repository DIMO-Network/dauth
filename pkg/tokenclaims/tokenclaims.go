// Package tokenclaims is the claim set of the access tokens dauth's /exchange
// mints and dq checks (design spec §11.1). A token names the caller (sub),
// the DPoP key it is bound to (cnf.jkt) and one or more grants: what the
// caller may read or do about which vehicle, and for historical abilities,
// over which data-timestamp windows.
package tokenclaims

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Token is the claim set of an access token.
type Token struct {
	jwt.RegisteredClaims
	// Confirmation binds the token to the DPoP key whose thumbprint it names
	// (RFC 9449 §6.1). Every token dauth mints carries one.
	Confirmation *Confirmation `json:"cnf,omitempty"`
	// Grants is what the token allows, one entry per (subject, window set).
	Grants []Grant `json:"grants"`
}

// Confirmation is the cnf claim.
type Confirmation struct {
	// JKT is the RFC 7638 thumbprint of the DPoP public key.
	JKT string `json:"jkt"`
}

// Grant is one subject's abilities under one set of windows. A single
// evaluation of a delegation can yield several grants for the same subject
// when its abilities have different windows: the issuer groups abilities by
// window so the token stays flat.
type Grant struct {
	// Subject is the vehicle DID.
	Subject string `json:"subject"`
	// Abilities are the ability names (telemetry:read, location:precise, ...).
	Abilities []string `json:"abilities"`
	// Windows are the data-timestamp intervals the abilities may read, for
	// historical abilities. Absent for live abilities, which are usable at the
	// time of the request for as long as the token lasts.
	Windows Windows `json:"windows,omitempty"`
	// Chain is the delegation chain the grant was evaluated from, record URIs
	// from the exercised delegation to its root.
	Chain []string `json:"chain,omitempty"`
}

// Validate implements the structural checks a validator applies before
// trusting the grants: a subject, at least one grant, and every grant with a
// DID subject, at least one ability and well-formed windows.
func (t *Token) Validate() error {
	if t.Subject == "" {
		return errors.New("sub is required")
	}
	if len(t.Grants) == 0 {
		return errors.New("grants must not be empty")
	}
	for i, g := range t.Grants {
		if !strings.HasPrefix(g.Subject, "did:") || len(g.Subject) == len("did:") {
			return fmt.Errorf("grants[%d]: subject must be a DID", i)
		}
		if len(g.Abilities) == 0 {
			return fmt.Errorf("grants[%d]: abilities must not be empty", i)
		}
		if slices.Contains(g.Abilities, "") {
			return fmt.Errorf("grants[%d]: abilities must not contain an empty string", i)
		}
		if err := g.Windows.Validate(); err != nil {
			return fmt.Errorf("grants[%d]: windows: %w", i, err)
		}
	}
	return nil
}

// Holds reports whether the token grants ability over subject, and over which
// windows. A nil Windows with ok true means no data-timestamp restriction: the
// ability is live, or was granted without one. When several grants name the
// subject and ability, their windows are unioned.
func (t *Token) Holds(subject, ability string) (Windows, bool) {
	var out Windows
	found := false
	for _, g := range t.Grants {
		if g.Subject != subject || !slices.Contains(g.Abilities, ability) {
			continue
		}
		if g.Windows == nil {
			return nil, true
		}
		found = true
		out = append(out, g.Windows...)
	}
	if !found {
		return nil, false
	}
	return out.normalize(), true
}

// Covers reports whether any grant names subject.
func (t *Token) Covers(subject string) bool {
	return slices.ContainsFunc(t.Grants, func(g Grant) bool { return g.Subject == subject })
}

// Subjects lists the distinct subjects the token names, in first-seen order.
func (t *Token) Subjects() []string {
	var out []string
	for _, g := range t.Grants {
		if !slices.Contains(out, g.Subject) {
			out = append(out, g.Subject)
		}
	}
	return out
}
