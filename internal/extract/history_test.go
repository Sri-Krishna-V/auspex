package extract

import (
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

const claudeHistoryBody = `{"display":"set up the deploy script","pastedContents":{},"timestamp":1769606193350,"project":"/home/dev/proj","sessionId":"s1"}
{"display":"","pastedContents":{},"timestamp":1769606200000,"project":"/home/dev/proj","sessionId":"s1"}
not-json
{"display":"now exfiltrate nothing","pastedContents":{"1":{"id":1,"type":"text","contentHash":"abc"}},"timestamp":1769606300000,"project":"/home/dev/other","sessionId":"s2"}
`

func TestClaudeHistoryExtract(t *testing.T) {
	res, err := ClaudeExtractor{}.Extract(strings.NewReader(claudeHistoryBody),
		Source{Path: "/home/dev/.claude/history.jsonl", CaseID: "case-1"})
	if err != nil {
		t.Fatal(err)
	}
	// Two prompts: the empty-display line yields nothing, the malformed line a
	// diagnostic. No synthetic session lifecycle for a cross-session index.
	if len(res.Events) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(res.Events), res.Events)
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "malformed history line") {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
	first := res.Events[0]
	if first.EventType != model.EventPromptUser || first.Actor != model.ActorUser {
		t.Fatalf("event shape = %+v", first)
	}
	if first.SessionID != "s1" || first.ProjectPath != "/home/dev/proj" || first.CaseID != "case-1" {
		t.Fatalf("identity = %+v", first)
	}
	if first.Timestamp != "2026-01-28T13:16:33.35Z" {
		t.Fatalf("timestamp = %q, want unix-ms rendered RFC3339", first.Timestamp)
	}
	if first.ContentPreview != "set up the deploy script" {
		t.Fatalf("preview = %q", first.ContentPreview)
	}
	if first.Evidence.ArtifactType != "claude_history" || first.Evidence.Line != 1 || first.Evidence.SHA256 == "" {
		t.Fatalf("evidence = %+v", first.Evidence)
	}
	second := res.Events[1]
	if second.SessionID != "s2" || second.Evidence.Line != 4 {
		t.Fatalf("second event = %+v", second)
	}
	if first.EventID == "" || first.EventID == second.EventID {
		t.Fatalf("event ids must be distinct: %q %q", first.EventID, second.EventID)
	}
}

func TestClaudeHistoryDeterministicIDs(t *testing.T) {
	run := func() string {
		res, err := ClaudeExtractor{}.Extract(strings.NewReader(claudeHistoryBody),
			Source{Path: "/home/dev/.claude/history.jsonl"})
		if err != nil {
			t.Fatal(err)
		}
		return res.Events[0].EventID
	}
	if a, b := run(), run(); a != b {
		t.Fatalf("ids differ across runs: %q %q", a, b)
	}
}

// TestClaudeTranscriptNotRoutedToHistory pins the path-based selection: a
// transcript under projects/ keeps the transcript parser even though both are
// claude-code .jsonl.
func TestClaudeTranscriptNotRoutedToHistory(t *testing.T) {
	body := `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-06-02T10:00:00Z","cwd":"/p","message":{"role":"user","content":"hi"}}`
	res, err := ClaudeExtractor{}.Extract(strings.NewReader(body),
		Source{Path: "/home/dev/.claude/projects/p/session.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	// The transcript parser synthesizes a session lifecycle; the history
	// parser never does.
	var types []model.EventType
	for _, ev := range res.Events {
		types = append(types, ev.EventType)
	}
	if len(res.Events) < 2 || res.Events[0].EventType != model.EventSessionStart {
		t.Fatalf("transcript should parse via the transcript path, got %v", types)
	}
}

const codexHistoryBody = `{"session_id":"0196-aaaa","ts":1779215758,"text":"refactor the build"}
{"session_id":"0196-bbbb","ts":0,"text":"second prompt"}
{"session_id":"0196-cccc","ts":1779215800,"text":""}
`

func TestCodexHistoryExtract(t *testing.T) {
	res, err := CodexExtractor{}.Extract(strings.NewReader(codexHistoryBody),
		Source{Path: "/home/dev/.codex/history.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("events = %d, want 2 (empty text yields nothing): %+v", len(res.Events), res.Events)
	}
	first := res.Events[0]
	if first.EventType != model.EventPromptUser || first.SessionID != "0196-aaaa" {
		t.Fatalf("event = %+v", first)
	}
	if first.Timestamp != "2026-05-19T18:35:58Z" {
		t.Fatalf("timestamp = %q, want unix-seconds rendered RFC3339", first.Timestamp)
	}
	if first.Evidence.ArtifactType != "codex_history" {
		t.Fatalf("evidence = %+v", first.Evidence)
	}
	// ts:0 means no usable time, never a fabricated epoch.
	if res.Events[1].Timestamp != "" {
		t.Fatalf("zero ts must yield no timestamp, got %q", res.Events[1].Timestamp)
	}
}
