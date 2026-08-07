package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// TestScanPromptHistoryArtifacts scans a fabricated home holding both
// prompt-history files and asserts each yields prompt.user events through its
// own parser — the end-to-end path for the history artifact coverage.
func TestScanPromptHistoryArtifacts(t *testing.T) {
	home := t.TempDir()
	files := map[string]string{
		".claude/history.jsonl": `{"display":"set up deploys","pastedContents":{},"timestamp":1769606193350,"project":"/home/dev/proj","sessionId":"s1"}` + "\n",
		".codex/history.jsonl":  `{"session_id":"0196-aaaa","ts":1779215758,"text":"refactor the build"}` + "\n",
	}
	for rel, body := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out, errb, code := runCLI("scan",
		"--path", filepath.Join(home, ".claude", "history.jsonl"),
		"--path", filepath.Join(home, ".codex", "history.jsonl"),
		"--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d (err=%s)", code, errb)
	}

	var prompts []model.Event
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var ev struct {
			RecordType string `json:"record_type"`
			model.Event
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		if ev.RecordType == "event" && ev.EventType == model.EventPromptUser {
			prompts = append(prompts, ev.Event)
		}
	}
	if len(prompts) != 2 {
		t.Fatalf("prompt.user events = %d, want one per history file:\n%s", len(prompts), out)
	}
	byAgent := map[string]model.Event{}
	for _, p := range prompts {
		byAgent[p.SourceAgent] = p
	}
	claude, codex := byAgent[model.AgentClaudeCode], byAgent[model.AgentCodex]
	if claude.Evidence.ArtifactType != "claude_history" || claude.SessionID != "s1" || claude.ProjectPath != "/home/dev/proj" {
		t.Fatalf("claude prompt = %+v", claude)
	}
	if codex.Evidence.ArtifactType != "codex_history" || codex.SessionID != "0196-aaaa" {
		t.Fatalf("codex prompt = %+v", codex)
	}
}
