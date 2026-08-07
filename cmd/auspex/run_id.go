package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

var runIDFallbackCounter atomic.Uint64

// runID returns a readable, process-safe identifier for one invocation.
func runID() string {
	prefix := "run-" + time.Now().UTC().Format("20060102T150405.000000000")
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err == nil {
		return prefix + "-" + hex.EncodeToString(suffix[:])
	}
	return fmt.Sprintf("%s-%d-%d", prefix, os.Getpid(), runIDFallbackCounter.Add(1))
}
