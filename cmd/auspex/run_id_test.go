package main

import (
	"strings"
	"testing"
)

func TestRunIDUniqueAndReadable(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := runID()
		if !strings.HasPrefix(id, "run-") {
			t.Fatalf("runID() = %q, want run- prefix", id)
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate run id %q", id)
		}
		seen[id] = struct{}{}
	}
}
