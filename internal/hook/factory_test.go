package hook

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// fac builds a Factory Droid hook payload.
func fac(toolName string, extra map[string]any) map[string]any {
	p := map[string]any{}
	if toolName != "" {
		p["tool_name"] = toolName
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// Generic top-level result keys are not part of Factory's documented hook
// payload. Only the documented nested tool_response shape may add result status.
func TestMapFactoryPostToolNoFabricatedMetadata(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		payload map[string]any
	}{
		{
			name: "status-error",
			tool: "some_tool",
			payload: map[string]any{
				"status": "error",
			},
		},
		{
			name: "code-and-duration",
			tool: "some_tool",
			payload: map[string]any{
				"code":        float64(1),
				"duration_ms": float64(50),
			},
		},
		{
			// "Bash" is not Factory's documented shell tool name ("Execute").
			name: "bash-named-tool-with-exit-code",
			tool: "Bash",
			payload: map[string]any{
				"command":     "echo hi",
				"exit_code":   float64(127),
				"duration_ms": float64(12),
				"is_error":    true,
			},
		},
		{
			name: "diff-and-is-error",
			tool: "Write",
			payload: map[string]any{
				"file_path": "/p/f",
				"diff":      "--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n",
				"is_error":  true,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Map(LifecycleFactoryPostTool, AgentFactory, model.AgentFactory, "e", fac(c.tool, c.payload))

			if ev.EventType != model.EventToolResult {
				t.Errorf("event_type = %q, want tool.result", ev.EventType)
			}
			if ev.ToolName != c.tool {
				t.Errorf("tool_name = %q, want %q", ev.ToolName, c.tool)
			}
			if ev.ExitCode != nil {
				t.Errorf("exit_code = %v, want nil", *ev.ExitCode)
			}
			if ev.DurationMs != nil {
				t.Errorf("duration_ms = %v, want nil", *ev.DurationMs)
			}
			if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
				t.Errorf("diff = %q/%d, want none", ev.DiffSHA256, ev.DiffBytes)
			}
			if hasTag(ev.Tags, model.TagToolError) {
				t.Errorf("tags = %v, want no tool_error", ev.Tags)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped factory event failed Validate: %v", err)
			}
		})
	}
}

// A Factory PostToolUse maps to tool.result with the correct ToolName, and an
// MCP-style tool name splits into MCPServer/MCPTool via the pure splitMCPName parse
// (no fabrication).
func TestMapFactoryPostToolNameAndMCPSplit(t *testing.T) {
	post := Map(LifecycleFactoryPostTool, AgentFactory, model.AgentFactory, "p", fac("some_tool", nil))
	if post.EventType != model.EventToolResult {
		t.Errorf("post event_type = %q, want tool.result", post.EventType)
	}
	if post.ToolName != "some_tool" {
		t.Errorf("post tool_name = %q, want some_tool", post.ToolName)
	}
	if post.MCPServer != "" || post.MCPTool != "" {
		t.Errorf("non-MCP tool must not populate MCP fields: server=%q tool=%q", post.MCPServer, post.MCPTool)
	}

	mcp := Map(LifecycleFactoryPostTool, AgentFactory, model.AgentFactory, "p2", fac("mcp__github__create_issue", nil))
	if mcp.EventType != model.EventToolResult {
		t.Errorf("mcp post event_type = %q, want tool.result", mcp.EventType)
	}
	if mcp.ToolName != "mcp__github__create_issue" {
		t.Errorf("mcp tool_name = %q", mcp.ToolName)
	}
	if mcp.MCPServer != "github" || mcp.MCPTool != "create_issue" {
		t.Errorf("MCP split = %q/%q, want github/create_issue", mcp.MCPServer, mcp.MCPTool)
	}
	assertHookProvenance(t, post)
	assertHookProvenance(t, mcp)
	if err := post.Validate(); err != nil {
		t.Errorf("post event failed Validate: %v", err)
	}
	if err := mcp.Validate(); err != nil {
		t.Errorf("mcp event failed Validate: %v", err)
	}
}

func TestMapFactoryDocumentedToolActions(t *testing.T) {
	tests := []struct {
		name string
		lc   Lifecycle
		tool string
		in   map[string]any
		want model.EventType
	}{
		{"execute pre", LifecycleFactoryPreTool, "Execute", map[string]any{"command": "cat .env"}, model.EventCommandExec},
		{"execute post", LifecycleFactoryPostTool, "Execute", map[string]any{"command": "false"}, model.EventCommandResult},
		{"read", LifecycleFactoryPreTool, "Read", map[string]any{"file_path": "/p/.env"}, model.EventFileRead},
		{"create", LifecycleFactoryPreTool, "Create", map[string]any{"file_path": "/p/new"}, model.EventFileWrite},
		{"fetch", LifecycleFactoryPreTool, "FetchUrl", map[string]any{"url": "https://example.com/x"}, model.EventNetworkIndicator},
		{"mcp", LifecycleFactoryPreTool, "mcp__github__create_issue", map[string]any{}, model.EventToolCall},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(tc.lc, AgentFactory, model.AgentFactory, "factory", fac(tc.tool, map[string]any{"tool_input": tc.in}))
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}

	failed := Map(LifecycleFactoryPostTool, AgentFactory, model.AgentFactory, "factory-fail", fac("Execute", map[string]any{
		"tool_input":    map[string]any{"command": "false"},
		"tool_response": map[string]any{"success": false},
	}))
	if !hasTag(failed.Tags, model.TagToolError) {
		t.Fatalf("Factory success:false tags = %v, want tool_error", failed.Tags)
	}
}

// ResolveLifecycle maps the exact Factory events auspex installs.
func TestResolveFactoryLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"SessionStart", LifecycleSessionStart},
		{"UserPromptSubmit", LifecyclePromptSubmit},
		{"PreToolUse", LifecycleFactoryPreTool},
		{"PostToolUse", LifecycleFactoryPostTool},
		{"Stop", LifecycleAssistant},
		{"SubagentStop", LifecycleSessionEnd},
		{"SessionEnd", LifecycleSessionEnd},
		// Case-insensitivity on the label.
		{"posttooluse", LifecycleFactoryPostTool},
		{"SESSIONSTART", LifecycleSessionStart},
		// The auspex lifecycle-arg spellings the installer wires verbatim.
		{"factory-pre-tool", LifecycleFactoryPreTool},
		{"factory-post-tool", LifecycleFactoryPostTool},
		{"session-start", LifecycleSessionStart},
		{"prompt-submit", LifecyclePromptSubmit},
		{"session-end", LifecycleSessionEnd},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentFactory, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(factory, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(factory, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	for _, bad := range []string{"PermissionRequest", "PostToolUseV2", "BeforeTool", "post-tool", ""} {
		if _, err := ResolveLifecycle(AgentFactory, bad); err == nil {
			t.Errorf("ResolveLifecycle(factory, %q) should error: not a wired Factory event", bad)
		}
	}
}

// Installer/runtime parity: for every event the installer wires (factoryHookEvents),
// the runtime resolver must map BOTH the raw Factory event name (the eventKey) AND
// the auspex lifecycle arg the installer writes into the command (the lifecycle
// field) to the same auspex Lifecycle. This pins that the two entry paths never
// drift — in particular that the tool moment stays on the Factory-specific
// (non-generic) lifecycle.
func TestFactoryInstallerResolverLifecycleParity(t *testing.T) {
	for _, ev := range factoryHookEvents {
		fromArg, err := ResolveLifecycle(AgentFactory, ev.lifecycle)
		if err != nil {
			t.Errorf("ResolveLifecycle(factory, lifecycle arg %q): %v", ev.lifecycle, err)
			continue
		}
		fromRaw, err := ResolveLifecycle(AgentFactory, ev.settingsKey)
		if err != nil {
			t.Errorf("ResolveLifecycle(factory, raw event %q): %v", ev.settingsKey, err)
			continue
		}
		if fromArg != fromRaw {
			t.Errorf("event %q: installer lifecycle arg %q resolves to %q but raw event resolves to %q (installer/runtime drift)",
				ev.settingsKey, ev.lifecycle, fromArg, fromRaw)
		}
	}
	// Factory tool hooks use Factory's own classifier.
	wired := map[string]string{}
	for _, ev := range factoryHookEvents {
		wired[ev.settingsKey] = ev.lifecycle
	}
	if wired["PostToolUse"] != string(LifecycleFactoryPostTool) {
		t.Errorf("PostToolUse wired to %q, want %q (must not use generic post-tool)", wired["PostToolUse"], LifecycleFactoryPostTool)
	}
	if wired["PreToolUse"] != string(LifecycleFactoryPreTool) {
		t.Errorf("PreToolUse wired to %q, want %q", wired["PreToolUse"], LifecycleFactoryPreTool)
	}
}
