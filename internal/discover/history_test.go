package discover

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// The prompt-history files are classified by their exact agent-root path:
// Claude's via the bare-.jsonl default, Codex's by an explicit claim that must
// win over the .codex bookkeeping guard — and any OTHER .jsonl under .codex is
// bookkeeping, never a Claude transcript.
func TestClassifyHistoryFiles(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"claude history", filepath.Join(".claude", "history.jsonl"), true, model.AgentClaudeCode},
		{"codex history", filepath.Join(".codex", "history.jsonl"), true, model.AgentCodex},
		{"stray jsonl under codex unclassified", filepath.Join(".codex", "log", "events.jsonl"), false, ""},
		{"history-named transcript under projects stays claude", filepath.Join(".claude", "projects", "p", "history.jsonl"), true, model.AgentClaudeCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Absolute and relative-root forms must classify identically.
			for _, path := range []string{filepath.Join(t.TempDir(), c.rel), c.rel} {
				art, ok := classify(path)
				if ok != c.wantOK {
					t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
				}
				if ok && art.Agent != c.wantAgt {
					t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
				}
			}
		})
	}
}

func TestDefaultRootsIncludesHistoryFiles(t *testing.T) {
	home := t.TempDir()
	for _, rel := range []string{claudeHistoryFile, codexHistoryFile} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	roots := DefaultRoots(home)
	for _, rel := range []string{claudeHistoryFile, codexHistoryFile} {
		if !slices.Contains(roots, filepath.Join(home, rel)) {
			t.Fatalf("roots missing %s: %v", rel, roots)
		}
	}
	// A directory squatting on the history path is not a file root.
	dirHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirHome, claudeHistoryFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if roots := DefaultRoots(dirHome); len(roots) != 0 {
		t.Fatalf("a directory must not join as a history root: %v", roots)
	}
}
