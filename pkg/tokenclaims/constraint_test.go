package tokenclaims

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func recordedAt(op, bound string) Constraint {
	return Constraint{LeftOperand: LeftOperandRecordedAt, Operator: op, RightOperand: bound}
}

func TestRecordedAtWindow(t *testing.T) {
	t.Run("resolves bounds with inclusivity", func(t *testing.T) {
		lower, upper, err := RecordedAtWindow([]Constraint{
			recordedAt(OperatorGteq, "2026-04-01T00:00:00Z"),
			recordedAt(OperatorLt, "2026-07-01T00:00:00Z"),
		})
		require.NoError(t, err)
		require.NotNil(t, lower)
		require.NotNil(t, upper)
		assert.True(t, lower.Time.Equal(ts("2026-04-01T00:00:00Z")))
		assert.True(t, lower.Inclusive)
		assert.True(t, upper.Time.Equal(ts("2026-07-01T00:00:00Z")))
		assert.False(t, upper.Inclusive)
	})

	t.Run("empty set is unbounded", func(t *testing.T) {
		lower, upper, err := RecordedAtWindow(nil)
		require.NoError(t, err)
		assert.Nil(t, lower)
		assert.Nil(t, upper)
	})

	t.Run("tightest bound wins", func(t *testing.T) {
		lower, upper, err := RecordedAtWindow([]Constraint{
			recordedAt(OperatorGteq, "2026-01-01T00:00:00Z"),
			recordedAt(OperatorGteq, "2026-04-01T00:00:00Z"),
			recordedAt(OperatorLteq, "2026-07-01T00:00:00Z"),
			recordedAt(OperatorLt, "2026-06-01T00:00:00Z"),
		})
		require.NoError(t, err)
		assert.True(t, lower.Time.Equal(ts("2026-04-01T00:00:00Z")))
		assert.True(t, upper.Time.Equal(ts("2026-06-01T00:00:00Z")))
		assert.False(t, upper.Inclusive)
	})

	t.Run("exclusive beats inclusive at the same instant", func(t *testing.T) {
		lower, _, err := RecordedAtWindow([]Constraint{
			recordedAt(OperatorGteq, "2026-04-01T00:00:00Z"),
			recordedAt(OperatorGt, "2026-04-01T00:00:00Z"),
		})
		require.NoError(t, err)
		assert.False(t, lower.Inclusive)
	})

	t.Run("unknown left operand fails closed", func(t *testing.T) {
		_, _, err := RecordedAtWindow([]Constraint{
			{LeftOperand: "dimo:geofence", Operator: OperatorGteq, RightOperand: "2026-04-01T00:00:00Z"},
		})
		require.Error(t, err)
	})

	t.Run("unknown operator fails closed", func(t *testing.T) {
		_, _, err := RecordedAtWindow([]Constraint{
			{LeftOperand: LeftOperandRecordedAt, Operator: "isAnyOf", RightOperand: "2026-04-01T00:00:00Z"},
		})
		require.Error(t, err)
	})

	t.Run("non-timestamp operand fails closed", func(t *testing.T) {
		_, _, err := RecordedAtWindow([]Constraint{
			recordedAt(OperatorGteq, "last Tuesday"),
		})
		require.Error(t, err)
	})
}

func TestAllowsInterval(t *testing.T) {
	window := []Constraint{
		recordedAt(OperatorGteq, "2026-04-01T00:00:00Z"),
		recordedAt(OperatorLt, "2026-07-01T00:00:00Z"),
	}

	cases := []struct {
		name     string
		from, to string
		want     bool
	}{
		{"inside", "2026-05-01T00:00:00Z", "2026-06-01T00:00:00Z", true},
		{"exact window", "2026-04-01T00:00:00Z", "2026-07-01T00:00:00Z", true},
		{"starts too early", "2026-03-31T23:59:59Z", "2026-06-01T00:00:00Z", false},
		{"ends too late", "2026-05-01T00:00:00Z", "2026-07-01T00:00:00.000000001Z", false},
		{"entirely before", "2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AllowsInterval(window, ts(tc.from), ts(tc.to))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("exclusive lower bound rejects its own instant", func(t *testing.T) {
		got, err := AllowsInterval([]Constraint{recordedAt(OperatorGt, "2026-04-01T00:00:00Z")},
			ts("2026-04-01T00:00:00Z"), ts("2026-05-01T00:00:00Z"))
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("unbounded constraints allow anything", func(t *testing.T) {
		got, err := AllowsInterval(nil, ts("1970-01-01T00:00:00Z"), ts("2100-01-01T00:00:00Z"))
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("uninterpretable constraint fails closed", func(t *testing.T) {
		_, err := AllowsInterval([]Constraint{
			{LeftOperand: "dimo:geofence", Operator: OperatorGteq, RightOperand: "2026-04-01T00:00:00Z"},
		}, ts("2026-05-01T00:00:00Z"), ts("2026-06-01T00:00:00Z"))
		require.Error(t, err)
	})
}
