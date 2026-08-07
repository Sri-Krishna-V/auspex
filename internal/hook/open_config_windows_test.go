//go:build windows

package hook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenHookConfigMissingIsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "settings.json")
	_, err := openHookConfig(path)
	if !os.IsNotExist(err) {
		t.Fatalf("openHookConfig error = %v, want missing-file classification", err)
	}
}
