package hook

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func TestResolveVSCodeLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"SessionStart", LifecycleSessionStart},
		{"UserPromptSubmit", LifecyclePromptSubmit},
		{"UserPromptSubmitted", LifecyclePromptSubmit},
		{"PreToolUse", LifecycleVSCodePreTool},
		{"PostToolUse", LifecycleVSCodePostTool},
		{"SubagentStart", LifecycleSessionStart},
		{"SubagentStop", LifecycleSessionEnd},
		{"Stop", LifecycleSessionEnd},
		{"vscode-pre-tool", LifecycleVSCodePreTool},
		{"vscode-post-tool", LifecycleVSCodePostTool},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentVSCode, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(vscode, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(vscode, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	for _, bad := range []string{"PreToolUseV2", "NotAPrompt", "tooluse", ""} {
		if _, err := ResolveLifecycle(AgentVSCode, bad); err == nil {
			t.Errorf("ResolveLifecycle(vscode, %q) should error", bad)
		}
	}
}

func TestMapVSCodeEvents(t *testing.T) {
	const eventID = "hook-vscode-1"
	tests := []struct {
		name    string
		event   string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name:  "prompt with workspace root",
			event: "UserPromptSubmit",
			payload: map[string]any{
				"sessionId":      "vscode-session",
				"prompt":         "run tests",
				"workspaceRoots": []any{"/repo"},
			},
			want: model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.SourceAgent != model.AgentVSCode {
					t.Errorf("source_agent = %q, want vscode", ev.SourceAgent)
				}
				if ev.ProjectPath != "/repo" {
					t.Errorf("project_path = %q, want /repo", ev.ProjectPath)
				}
				if ev.ContentPreview != "run tests" {
					t.Errorf("content_preview = %q", ev.ContentPreview)
				}
			},
		},
		{
			name:  "pre runCommand -> command.exec",
			event: "PreToolUse",
			payload: map[string]any{
				"sessionId": "vscode-session",
				"cwd":       "/repo",
				"tool_name": "runCommand",
				"tool_input": map[string]any{
					"command": "go test ./...",
				},
			},
			want: model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "go test ./..." {
					t.Errorf("command = %q", ev.Command)
				}
				if ev.ToolName != "runCommand" {
					t.Errorf("tool_name = %q", ev.ToolName)
				}
			},
		},
		{
			name:  "post runCommand -> command.result",
			event: "PostToolUse",
			payload: map[string]any{
				"sessionId": "vscode-session",
				"toolName":  "runCommand",
				"toolInput": map[string]any{"command": "false"},
				"toolResponse": map[string]any{
					"exitCode":    float64(1),
					"duration_ms": float64(25),
				},
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "false" {
					t.Errorf("command = %q", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 25 {
					t.Errorf("duration_ms = %v, want 25", ev.DurationMs)
				}
			},
		},
		{
			name:  "file read",
			event: "PreToolUse",
			payload: map[string]any{
				"toolName":  "readFile",
				"toolInput": map[string]any{"filePath": "/repo/main.go"},
			},
			want: model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/repo/main.go" {
					t.Errorf("file_path = %q", ev.FilePath)
				}
			},
		},
		{
			name:  "file edit result",
			event: "PostToolUse",
			payload: map[string]any{
				"toolName": "editFile",
				"toolInput": map[string]any{
					"filePath": "/repo/main.go",
					"edits": []any{
						map[string]any{"oldString": "old", "newString": "new"},
					},
				},
			},
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" || ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result repeated action fields: %+v", ev)
				}
			},
		},
		{
			name:  "unknown mcp tool keeps split",
			event: "PreToolUse",
			payload: map[string]any{
				"toolName": "mcp__github__create_issue",
			},
			want: model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q", ev.MCPServer, ev.MCPTool)
				}
			},
		},
		{
			name:  "subagent start stamps sub_agent",
			event: "SubagentStart",
			payload: map[string]any{
				"sessionId": "vscode-session",
				"cwd":       "/repo",
				"subagent":  "reviewer",
			},
			want: model.EventSessionStart,
			check: func(t *testing.T, ev model.Event) {
				if ev.SubAgent != "reviewer" {
					t.Errorf("sub_agent = %q, want reviewer", ev.SubAgent)
				}
			},
		},
		{
			name:  "subagent stop stamps sub_agent",
			event: "SubagentStop",
			payload: map[string]any{
				"sessionId": "vscode-session",
				"cwd":       "/repo",
				"subagent":  "reviewer",
			},
			want: model.EventSessionEnd,
			check: func(t *testing.T, ev model.Event) {
				if ev.SubAgent != "reviewer" {
					t.Errorf("sub_agent = %q, want reviewer", ev.SubAgent)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := ResolveLifecycle(AgentVSCode, tc.event)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			ev := Map(lc, AgentVSCode, model.AgentVSCode, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("mapped vscode event failed Validate: %v", err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestVSCodePassthroughIsEmpty(t *testing.T) {
	if resp := PassthroughResponse(AgentVSCode, LifecycleVSCodePreTool); len(resp) != 0 {
		t.Fatalf("vscode passthrough = %#v, want empty object", resp)
	}
}

func countVSCodeAuspexHooks(hooks map[string][]json.RawMessage) int {
	n := 0
	for _, entries := range hooks {
		for _, raw := range entries {
			if entryIsAuspex(raw) {
				n++
			}
		}
	}
	return n
}

func TestVSCodeInstallStatusUninstallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".copilot", "hooks", "auspex.json")
	rep, err := Install(AgentVSCode, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want installed+changed", rep)
	}
	vs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("read shared hook settings: %v", err)
	}
	if got, want := countVSCodeAuspexHooks(vs.hooks), len(copilotHookEvents); got != want {
		t.Fatalf("installed %d vscode hooks, want %d", got, want)
	}
	for _, entries := range vs.hooks {
		for _, raw := range entries {
			var entry cursorHookEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				t.Fatalf("unmarshal entry: %v", err)
			}
			if entryIsAuspex(raw) {
				if !strings.Contains(hookCommandText(entry.Command), "--agent copilot") {
					t.Errorf("shared command missing --agent copilot: %s", entry.Command)
				}
			}
		}
	}
	if rep := Status(AgentVSCode, path); !rep.Installed {
		t.Fatalf("status after install = not installed: %+v", rep)
	}
	if _, err := Uninstall(AgentVSCode, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	vs, err = readCursorSettings(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if got := countVSCodeAuspexHooks(vs.hooks); got != 0 {
		t.Fatalf("vscode hooks remain after uninstall: %d", got)
	}
}
