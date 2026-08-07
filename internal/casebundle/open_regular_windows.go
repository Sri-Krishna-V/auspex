//go:build windows

package casebundle

import (
	"errors"
	"fmt"
	"os"

	"github.com/Sri-Krishna-V/auspex/internal/winfile"
)

func openRegularFile(path string) (*os.File, error) {
	f, err := winfile.OpenRegular(path)
	if err != nil {
		if errors.Is(err, winfile.ErrReparsePoint) {
			return nil, fmt.Errorf("symlink or reparse point not allowed")
		}
		return nil, err
	}
	return f, nil
}
