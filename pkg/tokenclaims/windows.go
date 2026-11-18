package tokenclaims

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Window is one half-open interval [Start, End) of data timestamps. A nil
// Start or End is unbounded on that side. It encodes as [start|null, end|null],
// the same shape the org host's coverage uses for its interval sets.
type Window struct {
	Start *time.Time
	End   *time.Time
}

// MarshalJSON encodes the window as [start|null, end|null].
func (w Window) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]*time.Time{w.Start, w.End})
}

// UnmarshalJSON decodes [start|null, end|null].
func (w *Window) UnmarshalJSON(b []byte) error {
	var pair [2]*time.Time
	if err := json.Unmarshal(b, &pair); err != nil {
		return err
	}
	w.Start, w.End = pair[0], pair[1]
	return nil
}

// Contains reports whether t falls inside the window.
func (w Window) Contains(t time.Time) bool {
	if w.Start != nil && t.Before(*w.Start) {
		return false
	}
	if w.End != nil && !t.Before(*w.End) {
		return false
	}
	return true
}

func (w Window) empty() bool {
	return w.Start != nil && w.End != nil && !w.Start.Before(*w.End)
}

// Windows is a set of windows. As minted it is sorted and non-overlapping;
// Validate checks that on the way in.
type Windows []Window

// Validate checks that every window is non-empty and the set is sorted and
// disjoint.
func (ws Windows) Validate() error {
	for i, w := range ws {
		if w.empty() {
			return fmt.Errorf("window %d is empty", i)
		}
		if i == 0 {
			continue
		}
		prev := ws[i-1]
		if prev.End == nil || w.Start == nil || w.Start.Before(*prev.End) {
			return errors.New("windows must be sorted and disjoint")
		}
	}
	return nil
}

// Contains reports whether t falls inside any window.
func (ws Windows) Contains(t time.Time) bool {
	return slices.ContainsFunc(ws, func(w Window) bool { return w.Contains(t) })
}

// Clamp intersects the half-open range [from, to) with the windows and returns
// the pieces that remain, in order. An empty result means nothing in the range
// is covered; more than one piece means the range straddles a gap.
func (ws Windows) Clamp(from, to time.Time) Windows {
	return ws.ClampOpen(&from, &to)
}

// ClampOpen is Clamp for a range that may be unbounded on either side: a nil
// from or to is no bound. A piece keeps a nil side only when both the range
// and the window are unbounded there.
func (ws Windows) ClampOpen(from, to *time.Time) Windows {
	var out Windows
	for _, w := range ws {
		start, end := from, to
		if w.Start != nil && (start == nil || w.Start.After(*start)) {
			start = w.Start
		}
		if w.End != nil && (end == nil || w.End.Before(*end)) {
			end = w.End
		}
		if start != nil && end != nil && !start.Before(*end) {
			continue
		}
		piece := Window{}
		if start != nil {
			s := *start
			piece.Start = &s
		}
		if end != nil {
			e := *end
			piece.End = &e
		}
		out = append(out, piece)
	}
	return out
}

// normalize sorts the windows and merges any that overlap or touch.
func (ws Windows) normalize() Windows {
	if len(ws) == 0 {
		return Windows{}
	}
	sorted := slices.Clone(ws)
	slices.SortFunc(sorted, func(a, b Window) int {
		switch {
		case a.Start == nil && b.Start == nil:
			return 0
		case a.Start == nil:
			return -1
		case b.Start == nil:
			return 1
		default:
			return a.Start.Compare(*b.Start)
		}
	})
	out := Windows{sorted[0]}
	for _, w := range sorted[1:] {
		last := &out[len(out)-1]
		if last.End != nil && (w.Start == nil || !w.Start.After(*last.End)) || last.End == nil {
			if last.End != nil && (w.End == nil || w.End.After(*last.End)) {
				last.End = w.End
			}
			continue
		}
		out = append(out, w)
	}
	return out
}
