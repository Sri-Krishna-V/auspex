//go:build windows

package discover

import (
	"errors"
	"os"

	"github.com/Sri-Krishna-V/auspex/internal/winfile"
)

func openRegular(path string) (*os.File, error) {
	f, err := winfile.OpenRegular(path)
	if err != nil {
		if errors.Is(err, winfile.ErrReparsePoint) {
			return nil, errNotRegular
		}
		return nil, err
	}
	return f, nil
}
