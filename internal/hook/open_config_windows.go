//go:build windows

package hook

import (
	"errors"
	"fmt"
	"os"

	"github.com/Sri-Krishna-V/auspex/internal/winfile"
)

func openHookConfig(path string) (*os.File, error) {
	f, err := winfile.OpenRegular(path)
	if err != nil {
		// Keep missing files classifiable by callers that create a config on
		// first install. os.IsNotExist does not unwrap arbitrary fmt errors.
		if errors.Is(err, os.ErrNotExist) {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return nil, fmt.Errorf("%s: hook config is not a regular file: %w", path, err)
	}
	return f, nil
}
