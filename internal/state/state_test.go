package state

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "auspex.db"), time.Second)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestBoltHandleAvailable(t *testing.T) {
	db := openTemp(t)
	if db.Bolt() == nil {
		t.Fatalf("Bolt returned nil")
	}
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open("", time.Second); err == nil {
		t.Fatalf("expected error for empty path")
	}
}

func TestCloseIdempotentAndNilSafe(t *testing.T) {
	var nilDB *DB
	if err := nilDB.Close(); err != nil {
		t.Fatalf("nil Close should be nil, got %v", err)
	}
	db, err := Open(filepath.Join(t.TempDir(), "n.db"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("double close should be nil, got %v", err)
	}
}

func TestOpenTightensExistingFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auspex.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	db, err := Open(path, time.Second)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}
}
