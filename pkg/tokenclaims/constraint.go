package tokenclaims

import (
	"fmt"
	"time"
)

// This file defines the ODRL constraint atom under the DIMO profile
// (https://ns.dimo.co/odrl/v1) and its canonical evaluator. The same struct
// appears in two places: per-permission constraints inside an ODRL grant
// document, and — copied verbatim at exchange time — inside a permission
// token's scoped_permissions claim. There is deliberately no translation step
// between the two; the exchange verifies and consumes the grant's policy
// envelope and forwards the surviving data-level constraint atoms untouched.
//
// Consumers MUST be fail-closed: a scoped permission whose constraints they
// cannot fully interpret (unknown left operand, operator, or timestamp format)
// grants nothing. RecordedAtWindow returns an error in exactly those cases.

const (
	// LeftOperandRecordedAt constrains the recording timestamps of the data a
	// permission may read: the permission covers only data points whose
	// timestamp satisfies the comparison. It is defined by the DIMO ODRL
	// profile and is distinct from the ODRL core dateTime operand, which
	// bounds when a grant may be exercised.
	LeftOperandRecordedAt = "dimo:recordedAt"

	// OperatorGteq accepts values greater than or equal to the right operand.
	OperatorGteq = "gteq"
	// OperatorGt accepts values strictly greater than the right operand.
	OperatorGt = "gt"
	// OperatorLteq accepts values less than or equal to the right operand.
	OperatorLteq = "lteq"
	// OperatorLt accepts values strictly less than the right operand.
	OperatorLt = "lt"
)

// Constraint is a single ODRL constraint atom restricted to the DIMO profile:
// a comparison between a named left operand and a literal right operand.
// Multiple constraints are conjunctive, per the ODRL model.
type Constraint struct {
	LeftOperand  string `json:"leftOperand"`
	Operator     string `json:"operator"`
	RightOperand string `json:"rightOperand"`
}

// ScopedPermission is a permission granted subject to constraints. Scoped
// permissions never appear in the flat permissions claim: a consumer that
// does not understand a constraint must not be able to mistake the grant for
// an unconditional one.
type ScopedPermission struct {
	Name       string       `json:"name"`
	Constraint []Constraint `json:"constraint"`
}

// TimeBound is one end of a data-timestamp window resolved from a constraint
// set. Inclusive reports whether the bound itself is inside the window (gteq/
// lteq) or outside it (gt/lt).
type TimeBound struct {
	Time      time.Time
	Inclusive bool
}

// RecordedAtWindow resolves a conjunctive constraint set into the lower and
// upper bounds it places on data-recording timestamps. A nil bound means the
// window is unbounded on that side; overlapping constraints resolve to the
// tightest bound.
//
// It is fail-closed: any constraint with an unrecognized left operand or
// operator, or a right operand that is not an RFC 3339 timestamp, is an
// error. Callers must treat an error as denying access entirely, never as a
// constraint to skip.
func RecordedAtWindow(constraints []Constraint) (lower, upper *TimeBound, err error) {
	for i, c := range constraints {
		if c.LeftOperand != LeftOperandRecordedAt {
			return nil, nil, fmt.Errorf("constraint %d: unrecognized left operand %q", i, c.LeftOperand)
		}
		bound, parseErr := time.Parse(time.RFC3339, c.RightOperand)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("constraint %d: right operand is not an RFC 3339 timestamp: %w", i, parseErr)
		}
		switch c.Operator {
		case OperatorGteq:
			lower = tighterLower(lower, TimeBound{Time: bound, Inclusive: true})
		case OperatorGt:
			lower = tighterLower(lower, TimeBound{Time: bound, Inclusive: false})
		case OperatorLteq:
			upper = tighterUpper(upper, TimeBound{Time: bound, Inclusive: true})
		case OperatorLt:
			upper = tighterUpper(upper, TimeBound{Time: bound, Inclusive: false})
		default:
			return nil, nil, fmt.Errorf("constraint %d: unrecognized operator %q", i, c.Operator)
		}
	}
	return lower, upper, nil
}

// AllowsInterval reports whether every instant in the half-open interval
// [from, to) satisfies all constraints. Like RecordedAtWindow it is
// fail-closed, returning an error for any constraint it cannot interpret.
func AllowsInterval(constraints []Constraint, from, to time.Time) (bool, error) {
	lower, upper, err := RecordedAtWindow(constraints)
	if err != nil {
		return false, err
	}
	if lower != nil {
		if lower.Inclusive && from.Before(lower.Time) {
			return false, nil
		}
		if !lower.Inclusive && !from.After(lower.Time) {
			return false, nil
		}
	}
	// Every point in [from, to) is strictly before to, so to <= bound suffices
	// for both inclusive and exclusive upper bounds.
	if upper != nil && to.After(upper.Time) {
		return false, nil
	}
	return true, nil
}

// AllowsAt reports whether the instant t satisfies all constraints. Like
// RecordedAtWindow it is fail-closed, returning an error for any constraint it
// cannot interpret.
func AllowsAt(constraints []Constraint, t time.Time) (bool, error) {
	lower, upper, err := RecordedAtWindow(constraints)
	if err != nil {
		return false, err
	}
	if lower != nil {
		if lower.Inclusive && t.Before(lower.Time) {
			return false, nil
		}
		if !lower.Inclusive && !t.After(lower.Time) {
			return false, nil
		}
	}
	if upper != nil {
		if upper.Inclusive && t.After(upper.Time) {
			return false, nil
		}
		if !upper.Inclusive && !t.Before(upper.Time) {
			return false, nil
		}
	}
	return true, nil
}

// tighterLower returns the more restrictive of two lower bounds: the later
// time, with exclusive beating inclusive at the same instant.
func tighterLower(cur *TimeBound, next TimeBound) *TimeBound {
	if cur == nil || next.Time.After(cur.Time) || (next.Time.Equal(cur.Time) && !next.Inclusive) {
		return &next
	}
	return cur
}

// tighterUpper returns the more restrictive of two upper bounds: the earlier
// time, with exclusive beating inclusive at the same instant.
func tighterUpper(cur *TimeBound, next TimeBound) *TimeBound {
	if cur == nil || next.Time.Before(cur.Time) || (next.Time.Equal(cur.Time) && !next.Inclusive) {
		return &next
	}
	return cur
}
