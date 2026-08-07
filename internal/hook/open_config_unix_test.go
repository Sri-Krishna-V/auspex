//go:build unix

package hook

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadHookConfigRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookConfigFile(path); err == nil {
		t.Fatal("readHookConfigFile accepted a FIFO")
	}
}
