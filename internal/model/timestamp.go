package model

import (
	"strings"
	"time"
)

// CompareTimestamps orders source timestamps deterministically. Valid RFC3339
// values sort by instant, then by their original spelling; empty values sort
// first, followed by valid timestamps and then unparseable values.
func CompareTimestamps(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}

	at, aErr := time.Parse(time.RFC3339Nano, a)
	bt, bErr := time.Parse(time.RFC3339Nano, b)
	switch {
	case aErr == nil && bErr == nil:
		if at.Before(bt) {
			return -1
		}
		if at.After(bt) {
			return 1
		}
		return strings.Compare(a, b)
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}
