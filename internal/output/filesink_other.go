//go:build !unix && !windows

package output

import "os"

// openNoFollow falls back to a plain create open on platforms without
// O_NOFOLLOW. The symlink hardening is a no-op there; the fchmod tightening in
// NewFileSink still applies. appendMode selects append vs truncate, matching the
// unix build.
func openNoFollow(path string, perm os.FileMode, appendMode bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	return os.OpenFile(path, flags, perm)
}

// isNoFollowErr is always false where O_NOFOLLOW is unavailable.
func isNoFollowErr(error) bool { return false }

func writeFileLocked(f *os.File, p []byte) (int, error) {
	return f.Write(p)
}
