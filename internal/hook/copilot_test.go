package hook

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// ResolveLifecycle must map each GitHub Copilot CLI hook-event name onto the
// right auspex lifecycle using exact, case-insensitive names.
func TestResolveCopilotLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"PreToolUse", LifecycleCopilotPreTool},
		{"PostToolUse", LifecycleCopilotPostTool},
		{"PostToolUseFailure", LifecycleCopilotPostTool},
		{"UserPromptSubmit", LifecyclePromptSubmit},
		{"PermissionRequest", LifecycleCopilotPermission},
		{"SessionStart", LifecycleSessionStart},
		{"SubagentStart", LifecycleSessionStart},
		{"SubagentStop", LifecycleSessionEnd},
		{"SessionEnd", LifecycleSessionEnd},
		{"Stop", LifecycleAssistant},
		// Case-insensitivity on the label.
		{"pretooluse", LifecycleCopilotPreTool},
		{"POSTTOOLUSE", LifecycleCopilotPostTool},
		{"userpromptsubmitted", LifecyclePromptSubmit},
		// The auspex lifecycle-arg shorthands the installer may pass verbatim.
		{"pre-tool", LifecycleCopilotPreTool},
		{"pre_tool", LifecycleCopilotPreTool},
		{"post-tool", LifecycleCopilotPostTool},
		{"post_tool", LifecycleCopilotPostTool},
		{string(LifecycleAssistant), LifecycleAssistant},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentCopilot, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(copilot, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(copilot, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	// Copilot's event set is fixed and unambiguous, so resolution is EXACT, not a
	// substring match: a near-miss that merely contains a known name must surface
	// as an unknown-event operator error (which the cmd layer turns into exit 2),
	// never be silently accepted as the event it resembles. This guards the
	// substring→exact-match tightening so a regression cannot reintroduce the leak.
	for _, bad := range []string{
		"PreToolUseBroken",
		"PostToolUseV2",
		"UserPromptSubmittedV2",
		"XPreToolUse",
		"NotAPrompt",
		"prompt", // a bare substring of UserPromptSubmitted is no longer accepted
		"tooluse",
		"",
	} {
		if _, err := ResolveLifecycle(AgentCopilot, bad); err == nil {
			t.Errorf("ResolveLifecycle(copilot, %q) should error: not an exact Copilot event", bad)
		}
	}
}

func TestCopilotInstallerResolverLifecycleParity(t *testing.T) {
	for _, event := range copilotHookEvents {
		got, err := ResolveLifecycle(AgentCopilot, event.lifecycle)
		if err != nil {
			t.Errorf("installer lifecycle %q for %s is rejected: %v", event.lifecycle, event.event, err)
			continue
		}
		if got != Lifecycle(event.lifecycle) {
			t.Errorf("installer lifecycle %q resolved to %q", event.lifecycle, got)
		}
	}
}

// jsonArgs is the worst-realistic Copilot shape: toolArgs is a JSON-ENCODED
// STRING, not an object, and must be json.Unmarshal'd before its fields are read
// (toolInput() does this). Each test below seeds toolArgs this way so the decode
// path is the one exercised.
func cp(event, toolName, toolArgsJSON string, extra map[string]any) map[string]any {
	p := map[string]any{
		"hookEventName": event,
		"toolName":      toolName,
		"toolArgs":      toolArgsJSON,
		"cwd":           "/proj",
		"timestamp":     "2026-06-04T00:00:00Z",
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// Map must turn each Copilot event + tool_name variant into the right
// model.Event type with key fields resolved, exercising the real resolve→map
// path including the JSON-ENCODED-STRING toolArgs decode. Every mapped event must
// satisfy the model field co-occurrence contract (Validate).
func TestMapCopilotEvents(t *testing.T) {
	const eventID = "hook-copilot-1"

	tests := []struct {
		name    string
		event   string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name:    "UserPromptSubmitted → prompt.user",
			event:   "UserPromptSubmitted",
			payload: map[string]any{"hookEventName": "UserPromptSubmitted", "prompt": "read the   env file", "cwd": "/proj"},
			want:    model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorUser {
					t.Errorf("actor = %q, want user", ev.Actor)
				}
				if ev.ContentPreview != "read the env file" {
					t.Errorf("content_preview = %q, want collapsed prompt", ev.ContentPreview)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want /proj", ev.ProjectPath)
				}
			},
		},
		// Shell tool, all three name variants.
		{
			name:    "PreToolUse ShellCommand → command.exec (toolArgs decoded)",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "ShellCommand", `{"command":"cat .env"}`, nil),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" {
					t.Errorf("command = %q, want cat .env (decoded from toolArgs string)", ev.Command)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want /proj", ev.ProjectPath)
				}
			},
		},
		{
			name:    "PreToolUse run_shell_command with cmd field → command.exec",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "run_shell_command", `{"cmd":"ls -la"}`, nil),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "ls -la" {
					t.Errorf("command = %q, want ls -la (cmd fallback)", ev.Command)
				}
			},
		},
		{
			name:    "PostToolUse Bash → command.result with exit/duration",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "Bash", `{"command":"false"}`, map[string]any{"exit_code": float64(1), "duration_ms": float64(42)}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "false" {
					t.Errorf("command = %q, want false", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 42 {
					t.Errorf("duration_ms = %v, want 42", ev.DurationMs)
				}
			},
		},
		{
			name:    "PostToolUse ShellCommand with no exit reported → none fabricated",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "ShellCommand", `{"command":"echo hi"}`, nil),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ExitCode != nil {
					t.Errorf("exit_code = %v, want nil (none reported, none fabricated)", ev.ExitCode)
				}
				if ev.DurationMs != nil {
					t.Errorf("duration_ms = %v, want nil (none reported)", ev.DurationMs)
				}
			},
		},
		{
			name:    "PostToolUse with explicit error → tool_error tag",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "ShellCommand", `{"command":"false"}`, map[string]any{"error": "command failed"}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error (explicit error field)", ev.Tags)
				}
			},
		},
		// Read tool, content never stored.
		{
			name:    "PreToolUse ReadFile → file.read, content never stored",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "ReadFile", `{"path":"/proj/.env","content":"SECRET=abc123"}`, nil),
			want:    model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/.env" {
					t.Errorf("file_path = %q, want /proj/.env", ev.FilePath)
				}
				if ev.ContentPreview != "" {
					t.Errorf("content_preview = %q, want empty (read content never stored)", ev.ContentPreview)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("file.read must carry no diff: %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "PostToolUse read_file → tool.result",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "read_file", `{"filePath":"/proj/main.go"}`, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" {
					t.Errorf("tool.result must not repeat file_path, got %q", ev.FilePath)
				}
			},
		},
		// Write tool: diff from edits when present, none fabricated otherwise.
		{
			name:    "PreToolUse WriteFile no edits → file.write, no fabricated diff",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "WriteFile", `{"path":"/proj/y.go","content":"package main"}`, nil),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/y.go" {
					t.Errorf("file_path = %q, want /proj/y.go", ev.FilePath)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("a plain content write carries no edits → no diff, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "PostToolUse EditFile → tool.result",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "EditFile", `{"path":"/proj/x.go","edits":[{"old_string":"foo","new_string":"bar"}]}`, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" || ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result repeated action fields: %+v", ev)
				}
			},
		},
		{
			name:    "PostToolUse Write → tool.result",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "Write", `{"path":"/proj/z.go","edits":[{"old_string":"gone","new_string":""}]}`, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result must not repeat a diff, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		// Web tool → network.indicator.
		{
			name:    "PreToolUse WebFetch → network.indicator",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "WebFetch", `{"url":"https://evil.example/x"}`, nil),
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "https://evil.example/x" {
					t.Errorf("url = %q", ev.URL)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		{
			name:    "PreToolUse WebSearch with query → network.indicator preview",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "WebSearch", `{"query":"how to exfiltrate"}`, nil),
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "" {
					t.Errorf("url = %q, want empty (search carries a query, not a url)", ev.URL)
				}
				if ev.ContentPreview != "how to exfiltrate" {
					t.Errorf("content_preview = %q, want the query text", ev.ContentPreview)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		// Unknown / MCP tool → generic tool vocabulary.
		{
			name:    "PreToolUse unknown tool → tool.call",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "SomeCustomTool", `{"foo":"bar"}`, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "SomeCustomTool" {
					t.Errorf("tool_name = %q, want SomeCustomTool", ev.ToolName)
				}
			},
		},
		{
			name:    "PostToolUse unknown tool → tool.result",
			event:   "PostToolUse",
			payload: cp("PostToolUse", "SomeCustomTool", `{"foo":"bar"}`, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "SomeCustomTool" {
					t.Errorf("tool_name = %q, want SomeCustomTool", ev.ToolName)
				}
			},
		},
		{
			name:    "PreToolUse mcp-named tool → tool.call splits server/tool",
			event:   "PreToolUse",
			payload: cp("PreToolUse", "mcp__github__create_issue", `{"title":"x"}`, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := ResolveLifecycle(AgentCopilot, tc.event)
			if err != nil {
				t.Fatalf("ResolveLifecycle(%q): %v", tc.event, err)
			}
			ev := Map(lc, AgentCopilot, model.AgentCopilot, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SourceAgent != model.AgentCopilot {
				t.Errorf("source_agent = %q, want copilot", ev.SourceAgent)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped copilot %q event failed Validate: %v", tc.event, err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestMapCopilotCurrentToolNames(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]any
		want  model.EventType
	}{
		{name: "bash", input: map[string]any{"command": "pwd"}, want: model.EventCommandExec},
		{name: "powershell", input: map[string]any{"command": "Get-Location"}, want: model.EventCommandExec},
		{name: "view", input: map[string]any{"path": "/p/a.go"}, want: model.EventFileRead},
		{name: "create", input: map[string]any{"path": "/p/a.go"}, want: model.EventFileWrite},
		{name: "edit", input: map[string]any{"path": "/p/a.go"}, want: model.EventFileWrite},
		{name: "web_fetch", input: map[string]any{"url": "https://example.com"}, want: model.EventNetworkIndicator},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"toolName": tc.name, "toolArgs": tc.input}
			ev := Map(LifecycleCopilotPreTool, AgentCopilot, model.AgentCopilot, "e", payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if err := ev.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMapSharedCopilotHookRetainsVSCodeSourceAndFiles(t *testing.T) {
	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "editFiles",
		"tool_input": map[string]any{
			"files": []any{"/p/a.go", "/p/b.go"},
		},
	}
	events := MapEvents(LifecycleCopilotPreTool, AgentCopilot, model.AgentCopilot, "e", payload)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per file", events)
	}
	for i, ev := range events {
		if ev.SourceAgent != model.AgentVSCode {
			t.Errorf("event %d source_agent = %q, want vscode", i, ev.SourceAgent)
		}
		if ev.EventType != model.EventFileWrite {
			t.Errorf("event %d type = %q, want file.write", i, ev.EventType)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d: %v", i, err)
		}
	}
	if events[0].FilePath != "/p/a.go" || events[1].FilePath != "/p/b.go" {
		t.Fatalf("file paths = %q, %q", events[0].FilePath, events[1].FilePath)
	}
}

// A malformed toolArgs string (not valid JSON) must degrade safely:
// copilotToolArgs() decodes nothing, the family event is still produced with empty
// value fields, and the event still validates — never a panic and never a
// fabricated value.
func TestMapCopilotMalformedToolArgsDegradesSafely(t *testing.T) {
	for _, tc := range []struct {
		event string
		tool  string
		want  model.EventType
	}{
		{"PreToolUse", "ShellCommand", model.EventCommandExec},
		{"PreToolUse", "ReadFile", model.EventFileRead},
		{"PreToolUse", "WriteFile", model.EventFileWrite},
		{"PreToolUse", "WebFetch", model.EventNetworkIndicator},
		{"PostToolUse", "Bash", model.EventCommandResult},
	} {
		lc, err := ResolveLifecycle(AgentCopilot, tc.event)
		if err != nil {
			t.Fatalf("ResolveLifecycle(%q): %v", tc.event, err)
		}
		// toolArgs is a non-JSON string — the decode must fail gracefully.
		payload := cp(tc.event, tc.tool, "this is not json {", nil)
		ev := Map(lc, AgentCopilot, model.AgentCopilot, "hook-bad", payload)
		if ev.EventType != tc.want {
			t.Errorf("%s/%s: event_type = %q, want %q", tc.event, tc.tool, ev.EventType, tc.want)
		}
		if ev.Command != "" || ev.FilePath != "" || ev.URL != "" {
			t.Errorf("%s/%s: malformed toolArgs must yield empty value fields, got cmd=%q path=%q url=%q", tc.event, tc.tool, ev.Command, ev.FilePath, ev.URL)
		}
		assertHookProvenance(t, ev)
		if err := ev.Validate(); err != nil {
			t.Errorf("%s/%s: event failed Validate: %v", tc.event, tc.tool, err)
		}
	}
}

func TestMapCopilotPascalCaseToolInputWins(t *testing.T) {
	lc, err := ResolveLifecycle(AgentCopilot, "PreToolUse")
	if err != nil {
		t.Fatalf("ResolveLifecycle: %v", err)
	}
	payload := cp("PreToolUse", "ShellCommand", `{"command":"echo from-toolargs"}`, map[string]any{
		"tool_input": map[string]any{"command": "cat .env"},
		"input":      map[string]any{"command": "cat .env"},
	})
	ev := Map(lc, AgentCopilot, model.AgentCopilot, "hook-wins", payload)
	if ev.EventType != model.EventCommandExec {
		t.Fatalf("event_type = %q, want command.exec", ev.EventType)
	}
	if ev.Command != "cat .env" {
		t.Errorf("command = %q, want cat .env from PascalCase tool_input", ev.Command)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event failed Validate: %v", err)
	}
}

// A Copilot event with an empty payload must still yield a well-formed,
// hook-stamped event so the live handler never fails the agent on a bad body.
func TestMapCopilotEmptyPayloadIsWellFormed(t *testing.T) {
	for _, ev := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmitted"} {
		lc, err := ResolveLifecycle(AgentCopilot, ev)
		if err != nil {
			t.Fatalf("ResolveLifecycle(%q): %v", ev, err)
		}
		got := Map(lc, AgentCopilot, model.AgentCopilot, "hook-x", map[string]any{})
		assertHookProvenance(t, got)
		if err := got.Validate(); err != nil {
			t.Errorf("empty %q event failed Validate: %v", ev, err)
		}
	}
}

// A write whose decoded toolArgs carries edits with no real text must NOT get a
// fabricated diff; a delete-only edit must. This mirrors the Cursor/Windsurf
// invariant but exercises the Copilot JSON-string decode path.
func TestCopilotWriteEditsDiffNoFabricationOnEmpty(t *testing.T) {
	cases := []struct {
		name     string
		args     string
		wantDiff bool
	}{
		{"empty edit map", `{"path":"/p/f","edits":[{}]}`, false},
		{"empty old and new", `{"path":"/p/f","edits":[{"old_string":"","new_string":""}]}`, false},
		{"delete-only edit", `{"path":"/p/f","edits":[{"old_string":"gone","new_string":""}]}`, true},
		{"plain content write, no edits", `{"path":"/p/f","content":"hello"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Map(LifecycleCopilotPreTool, AgentCopilot, model.AgentCopilot, "e", cp("PreToolUse", "WriteFile", c.args, nil))
			gotDiff := ev.DiffSHA256 != "" || ev.DiffBytes != 0
			if gotDiff != c.wantDiff {
				t.Errorf("diff present = %v (sha=%q bytes=%d), want %v", gotDiff, ev.DiffSHA256, ev.DiffBytes, c.wantDiff)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event failed Validate: %v", err)
			}
		})
	}
}

// Monitor mode emits no decision, preserving Copilot's own approval flow.
func TestCopilotPassthroughIsInert(t *testing.T) {
	resp := PassthroughResponse(AgentCopilot, LifecycleCopilotPreTool)
	if len(resp) != 0 {
		t.Errorf("passthrough = %v, want empty object", resp)
	}
	resp["x"] = 1
	if len(PassthroughResponse(AgentCopilot, LifecycleCopilotPreTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}
