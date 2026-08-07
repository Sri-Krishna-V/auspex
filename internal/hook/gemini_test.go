package hook

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// ResolveLifecycle must map each Gemini CLI hook-event name auspex wires onto the
// right auspex lifecycle. The match is EXACT (case-folded), so a near-miss
// surfaces as an unknown-event operator error rather than being silently accepted.
func TestResolveGeminiLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"BeforeTool", LifecycleGeminiPreTool},
		{"AfterTool", LifecycleGeminiPostTool},
		{"BeforeAgent", LifecyclePromptSubmit},
		{"AfterAgent", LifecycleAssistant},
		{"SessionStart", LifecycleSessionStart},
		{"SessionEnd", LifecycleSessionEnd},
		// Case-insensitivity on the label.
		{"beforetool", LifecycleGeminiPreTool},
		{"AFTERTOOL", LifecycleGeminiPostTool},
		{"sessionstart", LifecycleSessionStart},
		// The auspex lifecycle-arg spellings the installer wires verbatim.
		{"gemini-pre-tool", LifecycleGeminiPreTool},
		{"gemini-post-tool", LifecycleGeminiPostTool},
		{"session-start", LifecycleSessionStart},
		{"session-end", LifecycleSessionEnd},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentGemini, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(gemini, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(gemini, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	// Gemini fires a larger lifecycle set than auspex wires. Resolution is exact, so an unwired
	// event — or a near-miss that merely contains a known name — must surface as an
	// unknown-event operator error (exit 2 at the cmd layer), never be silently
	// accepted as the event it resembles.
	for _, bad := range []string{
		"BeforeModel",
		"AfterModel",
		"BeforeToolSelection",
		"PreCompress",
		"Notification",
		"BeforeToolX",
		"AfterToolUse",
		"tool",
		"",
	} {
		if _, err := ResolveLifecycle(AgentGemini, bad); err == nil {
			t.Errorf("ResolveLifecycle(gemini, %q) should error: not a wired Gemini event", bad)
		}
	}
}

// Installer/runtime parity: for every event the installer wires (geminiHookEvents),
// the runtime resolver must map BOTH the raw documented Gemini event name (the
// settingsKey, e.g. "BeforeTool") AND the auspex lifecycle arg the installer writes
// into the command (the lifecycle field, e.g. "gemini-pre-tool") to the same auspex
// Lifecycle — and onward to the same model.EventType. The installer wires the
// lifecycle arg verbatim, while Gemini at runtime fires the raw event name; this
// test pins that those two entry paths never drift apart for any wired event.
func TestGeminiInstallerResolverLifecycleParity(t *testing.T) {
	for _, ev := range geminiHookEvents {
		// The path the installer's command takes at runtime: the auspex lifecycle arg.
		fromArg, err := ResolveLifecycle(AgentGemini, ev.lifecycle)
		if err != nil {
			t.Errorf("ResolveLifecycle(gemini, lifecycle arg %q): %v", ev.lifecycle, err)
			continue
		}
		// The path Gemini itself takes: the raw event name (settingsKey).
		fromRaw, err := ResolveLifecycle(AgentGemini, ev.settingsKey)
		if err != nil {
			t.Errorf("ResolveLifecycle(gemini, raw event %q): %v", ev.settingsKey, err)
			continue
		}
		if fromArg != fromRaw {
			t.Errorf("event %q: installer lifecycle arg %q resolves to %q but raw event resolves to %q (installer/runtime drift)",
				ev.settingsKey, ev.lifecycle, fromArg, fromRaw)
			continue
		}
		// And both must yield the same mapped EventType, so any future divergence in
		// Map (not just ResolveLifecycle) is also caught.
		argEvent := Map(fromArg, AgentGemini, model.AgentGeminiCLI, "parity", map[string]any{})
		rawEvent := Map(fromRaw, AgentGemini, model.AgentGeminiCLI, "parity", map[string]any{})
		if argEvent.EventType != rawEvent.EventType {
			t.Errorf("event %q: event_type drift arg=%q raw=%q", ev.settingsKey, argEvent.EventType, rawEvent.EventType)
		}
	}
}

// gm builds a Gemini hook payload. Gemini's payload is snake_case like Claude's and
// Codex's: tool_input is an OBJECT, tool_response carries structured result fields,
// and cwd/session_id sit at the top level.
func gm(event, toolName string, toolInput map[string]any, extra map[string]any) map[string]any {
	p := map[string]any{
		"hook_event_name": event,
		"tool_name":       toolName,
		"tool_input":      toolInput,
		"cwd":             "/proj",
		"session_id":      "sess-1",
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// Map must turn each Gemini event + tool_name variant into the right model.Event
// type with key fields resolved, exercising the real resolve→map path. Every mapped
// event must satisfy the model field co-occurrence contract (Validate). The Gemini
// tool vocabulary (run_shell_command / read_file / write_file / replace / web_fetch
// / google_web_search) must classify identically to the at-rest extractor. Exit
// codes and tool-error flags come ONLY from structured fields, never inferred or
// fabricated when absent; reads never store content.
func TestMapGeminiEvents(t *testing.T) {
	const eventID = "hook-gemini-1"

	tests := []struct {
		name    string
		event   string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		// run_shell_command → command.exec / command.result.
		{
			name:    "BeforeTool run_shell_command → command.exec",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "run_shell_command", map[string]any{"command": "cat .env"}, nil),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" {
					t.Errorf("command = %q, want cat .env", ev.Command)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want /proj", ev.ProjectPath)
				}
			},
		},
		{
			name:    "AfterTool run_shell_command → command.result with structured exit/duration",
			event:   "AfterTool",
			payload: gm("AfterTool", "run_shell_command", map[string]any{"command": "false"}, map[string]any{"tool_response": map[string]any{"exit_code": float64(1), "duration_ms": float64(42)}}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "false" {
					t.Errorf("command = %q, want false", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1 (structured)", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 42 {
					t.Errorf("duration_ms = %v, want 42 (structured)", ev.DurationMs)
				}
			},
		},
		{
			name:    "AfterTool run_shell_command with no exit reported → none fabricated",
			event:   "AfterTool",
			payload: gm("AfterTool", "run_shell_command", map[string]any{"command": "echo hi"}, nil),
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
			// The tool-error tag comes ONLY from Gemini's nested tool_response, not from
			// an adjacent top-level key. A structured error inside tool_response tags.
			name:    "AfterTool run_shell_command with nested tool_response error → tool_error tag",
			event:   "AfterTool",
			payload: gm("AfterTool", "run_shell_command", map[string]any{"command": "false"}, map[string]any{"tool_response": map[string]any{"error": "command failed"}}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error (structured tool_response error)", ev.Tags)
				}
			},
		},
		{
			// HIGH-PRECISION CONTRACT: a top-level error key is NOT part of Gemini's
			// documented payload, so it must NOT set tool_error. Only Gemini's nested
			// tool_response carries the failure signal; with no tool_response the result
			// degrades to untagged rather than recovering an error from an adjacent shape.
			name:    "AfterTool run_shell_command with top-level error only → NO tool_error tag",
			event:   "AfterTool",
			payload: gm("AfterTool", "run_shell_command", map[string]any{"command": "false"}, map[string]any{"error": "command failed"}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want NO tool_error (top-level error is not Gemini's shape)", ev.Tags)
				}
			},
		},
		// read_file → file.read, content never stored.
		{
			name:    "BeforeTool read_file → file.read, content never stored",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "read_file", map[string]any{"file_path": "/proj/.env", "content": "SECRET=abc123"}, nil),
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
		// write_file / replace → file.write.
		{
			name:    "BeforeTool write_file → file.write",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "write_file", map[string]any{"file_path": "/proj/new.go"}, nil),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/new.go" {
					t.Errorf("file_path = %q, want /proj/new.go", ev.FilePath)
				}
				if ev.Command != "" {
					t.Errorf("file.write must carry no command, got %q", ev.Command)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("no structured diff reported → no diff, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "AfterTool replace → tool.result",
			event:   "AfterTool",
			payload: gm("AfterTool", "replace", map[string]any{"file_path": "/proj/y.go"}, map[string]any{"tool_response": map[string]any{"diff_sha256": testDiffSHA256, "diff_bytes": float64(12)}}),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" || ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result repeated action fields: %+v", ev)
				}
			},
		},
		// web_fetch carries the URL inside the free-text "prompt" arg.
		{
			name:    "BeforeTool web_fetch with explicit url → network.indicator",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "web_fetch", map[string]any{"url": "https://evil.example/x"}, nil),
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
			name:    "BeforeTool web_fetch with prompt only → preview, no fabricated url",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "web_fetch", map[string]any{"prompt": "fetch https://evil.example and summarize"}, nil),
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "" {
					t.Errorf("url = %q, want empty (no explicit url arg → none fabricated)", ev.URL)
				}
				if ev.ContentPreview != "fetch https://evil.example and summarize" {
					t.Errorf("content_preview = %q, want the prompt text", ev.ContentPreview)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		{
			name:    "BeforeTool google_web_search with query → network.indicator preview",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "google_web_search", map[string]any{"query": "how to exfiltrate"}, nil),
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
		// Unknown / MCP tool → generic tool vocabulary, narrow (no generic aliases).
		{
			name:    "BeforeTool unknown tool → tool.call, no alias promotion",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "some_custom_tool", map[string]any{"foo": "bar"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "some_custom_tool" {
					t.Errorf("tool_name = %q, want some_custom_tool", ev.ToolName)
				}
				if ev.Command != "" || ev.FilePath != "" || ev.URL != "" {
					t.Errorf("unknown tool must not be promoted to a typed action: cmd=%q path=%q url=%q", ev.Command, ev.FilePath, ev.URL)
				}
			},
		},
		{
			name:    "AfterTool unknown tool → tool.result",
			event:   "AfterTool",
			payload: gm("AfterTool", "some_custom_tool", map[string]any{"foo": "bar"}, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "some_custom_tool" {
					t.Errorf("tool_name = %q, want some_custom_tool", ev.ToolName)
				}
			},
		},
		{
			name:    "BeforeTool mcp-named tool → tool.call splits server/tool",
			event:   "BeforeTool",
			payload: gm("BeforeTool", "mcp__github__create_issue", map[string]any{"title": "x"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
			},
		},
		{
			name:  "BeforeTool structured remote MCP context → network.indicator",
			event: "BeforeTool",
			payload: gm("BeforeTool", "mcp_github_create_issue", map[string]any{"title": "x"}, map[string]any{
				"mcp_context": map[string]any{
					"server_name": "github",
					"tool_name":   "create_issue",
					"url":         "https://mcp.example/rpc",
				},
			}),
			want: model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" || ev.URL != "https://mcp.example/rpc" {
					t.Errorf("structured MCP fields = %q/%q %q", ev.MCPServer, ev.MCPTool, ev.URL)
				}
			},
		},
		{
			name:  "AfterTool structured MCP context → tool.result",
			event: "AfterTool",
			payload: gm("AfterTool", "mcp_github_create_issue", map[string]any{"title": "x"}, map[string]any{
				"mcp_context": map[string]any{"server_name": "github", "tool_name": "create_issue"},
			}),
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("structured MCP fields = %q/%q", ev.MCPServer, ev.MCPTool)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := ResolveLifecycle(AgentGemini, tc.event)
			if err != nil {
				t.Fatalf("ResolveLifecycle(%q): %v", tc.event, err)
			}
			ev := Map(lc, AgentGemini, model.AgentGeminiCLI, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SourceAgent != model.AgentGeminiCLI {
				t.Errorf("source_agent = %q, want gemini-cli", ev.SourceAgent)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped gemini %q event failed Validate: %v", tc.event, err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

// A non-zero exit code alone must NOT raise tool_error: the error flag is
// explicit-only (a clean command can exit non-zero and still not be "errored" in
// the agent's sense). This guards the no-inference rule for the structured path.
func TestMapGeminiExitCodeAloneIsNotToolError(t *testing.T) {
	payload := gm("AfterTool", "run_shell_command", map[string]any{"command": "false"}, map[string]any{
		"tool_response": map[string]any{"exit_code": float64(2)},
	})
	ev := Map(LifecycleGeminiPostTool, AgentGemini, model.AgentGeminiCLI, "e", payload)
	if ev.ExitCode == nil || *ev.ExitCode != 2 {
		t.Fatalf("exit_code = %v, want 2", ev.ExitCode)
	}
	if hasTag(ev.Tags, model.TagToolError) {
		t.Errorf("tags = %v, want NO tool_error from a non-zero exit alone", ev.Tags)
	}
}

// A write whose payload carries no structured diff must NOT get a fabricated
// digest — the edit body is never hashed at the hook boundary.
func TestMapGeminiWriteNoFabricatedDiff(t *testing.T) {
	for _, tool := range []string{"write_file", "replace"} {
		payload := gm("AfterTool", tool, map[string]any{"file_path": "/p/f", "content": "real body"}, nil)
		ev := Map(LifecycleGeminiPostTool, AgentGemini, model.AgentGeminiCLI, "e", payload)
		if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
			t.Errorf("%s: fabricated diff %q/%d, want none (no structured diff reported)", tool, ev.DiffSHA256, ev.DiffBytes)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: event failed Validate: %v", tool, err)
		}
	}
}

// A Gemini event with an empty payload must still yield a well-formed, hook-stamped
// event so the live handler never fails the agent on a bad body.
func TestMapGeminiEmptyPayloadIsWellFormed(t *testing.T) {
	for _, ev := range []string{"BeforeTool", "AfterTool", "SessionStart", "SessionEnd"} {
		lc, err := ResolveLifecycle(AgentGemini, ev)
		if err != nil {
			t.Fatalf("ResolveLifecycle(%q): %v", ev, err)
		}
		got := Map(lc, AgentGemini, model.AgentGeminiCLI, "hook-x", map[string]any{})
		assertHookProvenance(t, got)
		if err := got.Validate(); err != nil {
			t.Errorf("empty %q event failed Validate: %v", ev, err)
		}
	}
}

// An allowed Gemini hook prints an empty object, which leaves agent behavior
// unchanged. It must be a fresh map each call.
func TestGeminiPassthroughIsInert(t *testing.T) {
	resp := PassthroughResponse(AgentGemini, LifecycleGeminiPreTool)
	if len(resp) != 0 {
		t.Errorf("passthrough = %v, want empty object {}", resp)
	}
	resp["x"] = 1
	if len(PassthroughResponse(AgentGemini, LifecycleGeminiPreTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}
