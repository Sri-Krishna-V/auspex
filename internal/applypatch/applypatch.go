// Package applypatch parses the file directives in an apply_patch envelope.
package applypatch

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Change identifies one file operation. A move is a source deletion followed
// by a destination write.
type Change struct {
	Path   string
	Delete bool
}

// Parse returns file directives in source order. Diff hunk lines that resemble
// directives are ignored.
func Parse(patch string) []Change {
	lines := strings.Split(patch, "\n")
	hasEnvelope := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "*** Begin Patch" {
			hasEnvelope = true
			break
		}
	}

	inEnvelope := !hasEnvelope
	var changes []Change
	pendingUpdate := -1
	for _, raw := range lines {
		if strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") ||
			strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "@@") {
			continue
		}
		line := strings.TrimSpace(raw)
		if hasEnvelope {
			switch line {
			case "*** Begin Patch":
				inEnvelope = true
				continue
			case "*** End Patch":
				inEnvelope = false
				continue
			}
			if !inEnvelope {
				continue
			}
		}

		for _, directive := range []struct {
			prefix string
			kind   string
		}{
			{prefix: "*** Add File:", kind: "add"},
			{prefix: "*** Update File:", kind: "update"},
			{prefix: "*** Delete File:", kind: "delete"},
			{prefix: "*** Move to:", kind: "move"},
		} {
			if !strings.HasPrefix(line, directive.prefix) {
				continue
			}
			path := strings.TrimSpace(strings.TrimPrefix(line, directive.prefix))
			if path != "" {
				switch directive.kind {
				case "update":
					changes = append(changes, Change{Path: path})
					pendingUpdate = len(changes) - 1
				case "move":
					if pendingUpdate >= 0 {
						changes[pendingUpdate].Delete = true
					}
					changes = append(changes, Change{Path: path})
					pendingUpdate = -1
				default:
					changes = append(changes, Change{Path: path, Delete: directive.kind == "delete"})
					pendingUpdate = -1
				}
			}
			break
		}
	}
	return changes
}

// Digest returns the lowercase SHA-256 and byte length of patch. Empty input
// leaves both fields unset.
func Digest(patch string) (string, int) {
	if patch == "" {
		return "", 0
	}
	sum := sha256.Sum256([]byte(patch))
	return hex.EncodeToString(sum[:]), len(patch)
}
