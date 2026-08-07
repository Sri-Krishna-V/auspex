//go:build windows

package hook

import "github.com/Sri-Krishna-V/auspex/internal/winfile"

func replaceFile(from, to string) error {
	return winfile.Replace(from, to)
}
