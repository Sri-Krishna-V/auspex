//go:build windows

package casebundle

import "github.com/Sri-Krishna-V/auspex/internal/winfile"

func renameNoReplace(from, to string) error {
	return winfile.RenameNoReplace(from, to)
}
