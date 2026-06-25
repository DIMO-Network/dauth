// Package envx holds the small, dependency-free helpers for reading runtime
// configuration from the environment, following the dauth/din convention: pure
// env vars, defaults applied at the call site, and fail-fast parse errors so a
// misconfigured deployment never starts. The config packages compose these into
// their Config.
package envx

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// String returns the value of key, or def when it is unset or empty.
func String(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Int returns the value of key parsed as an int, def when it is unset, or an
// error naming the key when it is malformed.
func Int(key string, def int) (int, error) {
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

// Uint returns the value of key parsed as a uint64, def when it is unset, or an
// error naming the key when it is malformed.
func Uint(key string, def uint64) (uint64, error) {
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

// Duration returns the value of key parsed as a time.Duration, def when it is
// unset, or an error naming the key when it is malformed.
func Duration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return d, nil
}

// Numbered collects values from prefix+"1", prefix+"2", ... stopping at the
// first gap, so a contiguous, ordered key list comes straight from the
// environment without a separate count variable.
func Numbered(prefix string) []string {
	var out []string
	for i := 1; ; i++ {
		v := os.Getenv(prefix + strconv.Itoa(i))
		if v == "" {
			break
		}
		out = append(out, v)
	}
	return out
}

// List parses a comma-separated env value into a trimmed, non-empty slice.
func List(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
