package model

import (
	"slices"
	"sort"
	"testing"
)

func TestCompareTimestampsTotalOrder(t *testing.T) {
	values := []string{
		"not-a-time",
		"2026-06-02T10:00:00-05:00",
		"",
		"2026-06-02T14:30:00Z",
		"also-not-a-time",
		"2026-06-02T15:00:00Z",
	}
	want := []string{
		"",
		"2026-06-02T14:30:00Z",
		"2026-06-02T10:00:00-05:00",
		"2026-06-02T15:00:00Z",
		"also-not-a-time",
		"not-a-time",
	}

	for i := 0; i < 20; i++ {
		got := append([]string(nil), values...)
		if i%2 == 1 {
			slices.Reverse(got)
		}
		sort.Slice(got, func(i, j int) bool { return CompareTimestamps(got[i], got[j]) < 0 })
		if !slices.Equal(got, want) {
			t.Fatalf("order = %q, want %q", got, want)
		}
	}
}

func TestCompareTimestampsEqualInstantUsesRawTieBreak(t *testing.T) {
	a := "2026-06-02T10:00:00-05:00"
	b := "2026-06-02T15:00:00Z"
	if got := CompareTimestamps(a, b); got >= 0 {
		t.Fatalf("CompareTimestamps(%q, %q) = %d, want lexical tie-break", a, b, got)
	}
}
