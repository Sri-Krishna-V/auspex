//go:build !linux && !darwin && !windows

package casebundle

import "os"

// Release targets use platform-specific kernel-level no-replace renames. This
// fallback keeps other builds portable.
func renameNoReplace(from, to string) error {
	return os.Rename(from, to)
}
