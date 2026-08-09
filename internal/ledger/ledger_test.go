package ledger

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Sri-Krishna-V/auspex/internal/state"
)

// openTestDB opens a throwaway state database through internal/state, the same
// owner the hook and the inventory command go through, so the test exercises
// the real bucket layout rather than a bespoke bolt file.
func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"), time.Second)
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db.Bolt()
}

// TestReadIsEmptyBeforeAnyTouch pins the ordinary state of a machine where no
// hook has ever run: a nil map and no error, never a fabricated entry. This is
// what makes every row read "never" instead of "unknown" on a fresh endpoint.
func TestReadIsEmptyBeforeAnyTouch(t *testing.T) {
	got, err := Read(openTestDB(t))
	if err != nil {
		t.Fatalf("Read on a fresh database: %v", err)
	}
	if got != nil {
		t.Errorf("Read = %v, want nil map when the bucket is absent", got)
	}
}

func TestTouchRecordsPerAgentAndLastWriteWins(t *testing.T) {
	db := openTestDB(t)
	first := time.Date(2026, 3, 1, 9, 30, 0, 123456789, time.UTC)
	later := first.Add(2 * time.Hour)

	for _, tc := range []struct {
		agent string
		at    time.Time
	}{
		{"claude", first},
		{"codex", first.Add(time.Minute)},
		{"claude", later}, // same agent again: the stamp advances, not appends
	} {
		if err := Touch(db, tc.agent, tc.at); err != nil {
			t.Fatalf("Touch(%q): %v", tc.agent, err)
		}
	}
	// A blank agent id must not claim coverage for nothing.
	if err := Touch(db, "", first); err != nil {
		t.Fatalf("Touch with empty agent: %v", err)
	}

	got, err := Read(db)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Read = %v, want exactly the two touched agents", got)
	}
	if !got["claude"].Equal(later) {
		t.Errorf("claude = %v, want the later stamp %v (last write must win)", got["claude"], later)
	}
	if !got["codex"].Equal(first.Add(time.Minute)) {
		t.Errorf("codex = %v, want %v", got["codex"], first.Add(time.Minute))
	}
	if _, ok := got["gemini"]; ok {
		t.Error("an untouched agent must be absent, not zero-valued")
	}
}

// TestTouchStampsSurviveReopen proves the ledger is what the inventory command
// reads back in a later process — the whole point of persisting it.
func TestTouchStampsSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	at := time.Date(2026, 3, 1, 9, 30, 0, 0, time.UTC)

	db, err := state.Open(path, time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := Touch(db.Bolt(), "claude", at); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := state.Open(path, time.Second)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	got, err := Read(reopened.Bolt())
	if err != nil {
		t.Fatalf("Read after reopen: %v", err)
	}
	if !got["claude"].Equal(at) {
		t.Errorf("claude = %v after reopen, want %v", got["claude"], at)
	}
}

// TestReadRejectsUnparseableStamp locks the honest failure direction: a corrupt
// value fails the read (the caller reports "unknown") instead of being skipped,
// which would report "never" for an agent that has in fact been observed.
func TestReadRejectsUnparseableStamp(t *testing.T) {
	db := openTestDB(t)
	if err := Touch(db, "claude", time.Now()); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCoverage).Put([]byte("claude"), []byte("not-a-timestamp"))
	})
	if err != nil {
		t.Fatalf("corrupt stamp: %v", err)
	}
	if _, err := Read(db); err == nil {
		t.Error("Read = nil error on an unparseable stamp, want a failure")
	}
}
