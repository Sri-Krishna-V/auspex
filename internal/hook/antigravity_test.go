package hook

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func TestAntigravityControlResponses(t *testing.T) {
	pre := PassthroughResponse(AgentAntigravity, LifecycleAntigravityPreTool)
	if pre["decision"] != "ask" {
		t.Fatalf("pre-tool response = %#v, want decision ask", pre)
	}
	if got := PassthroughResponse(AgentAntigravity, LifecycleAntigravityPostTool); len(got) != 0 {
		t.Fatalf("post-tool response = %#v, want empty object", got)
	}
	stop := PassthroughResponse(AgentAntigravity, LifecycleStop)
	if stop["decision"] != "stop" {
		t.Fatalf("stop response = %#v, want decision stop", stop)
	}
}

func TestAntigravityDenyResponse(t *testing.T) {
	response, ok := DenyResponse(AgentAntigravity, "blocked by policy")
	if !ok || response["decision"] != "deny" || response["reason"] != "blocked by policy" {
		t.Fatalf("deny response = %#v, %v", response, ok)
	}
	if !EnforceEligible(AgentAntigravity, "PreToolUse", LifecycleAntigravityPreTool) {
		t.Fatal("PreToolUse should be enforce-eligible")
	}
}

func antigravityPayload(name string, args map[string]any) map[string]any {
	payload := map[string]any{
		"conversationId": "conversation-1",
		"workspacePaths": []any{"/workspace/project", "/workspace/other"},
		"stepIdx":        float64(7),
	}
	if name != "" {
		payload["toolCall"] = map[string]any{"name": name, "args": args}
	}
	return payload
}

func TestMapAntigravityDocumentedTools(t *testing.T) {
	tests := []struct {
		name         string
		tool         string
		args         map[string]any
		wantType     model.EventType
		wantCommand  string
		wantFile     string
		wantURL      string
		wantSubAgent string
	}{
		{name: "command", tool: "run_command", args: map[string]any{"CommandLine": "git status"}, wantType: model.EventCommandExec, wantCommand: "git status"},
		{name: "read", tool: "view_file", args: map[string]any{"AbsolutePath": "/workspace/project/.env"}, wantType: model.EventFileRead, wantFile: "/workspace/project/.env"},
		{name: "write", tool: "replace_file_content", args: map[string]any{"TargetFile": "/workspace/project/main.go"}, wantType: model.EventFileWrite, wantFile: "/workspace/project/main.go"},
		{name: "fetch", tool: "read_url_content", args: map[string]any{"Url": "https://example.com/a"}, wantType: model.EventNetworkIndicator, wantURL: "https://example.com/a"},
		{name: "subagent", tool: "invoke_subagent", args: map[string]any{"Subagents": []any{map[string]any{"Role": "reviewer"}}}, wantType: model.EventToolCall, wantSubAgent: "reviewer"},
		{name: "unknown", tool: "future_tool", args: map[string]any{}, wantType: model.EventToolCall},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := MapEvents(LifecycleAntigravityPreTool, AgentAntigravity, model.AgentAntigravity, "event-1", antigravityPayload(tc.tool, tc.args))[0]
			if ev.EventType != tc.wantType || ev.Command != tc.wantCommand || ev.FilePath != tc.wantFile || ev.URL != tc.wantURL {
				t.Errorf("event = %+v", ev)
			}
			if ev.ToolName != tc.tool {
				t.Errorf("tool_name = %q, want %q", ev.ToolName, tc.tool)
			}
			if ev.SubAgent != tc.wantSubAgent {
				t.Errorf("sub_agent = %q, want %q", ev.SubAgent, tc.wantSubAgent)
			}
			if ev.SessionID != "conversation-1" || ev.ProjectPath != "/workspace/project" || ev.ToolCallID != "step:7" {
				t.Errorf("common fields = session %q project %q call %q", ev.SessionID, ev.ProjectPath, ev.ToolCallID)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

func TestMapAntigravityPostToolUsesStepCorrelation(t *testing.T) {
	payload := antigravityPayload("", nil)
	payload["error"] = "exit status 1"
	ev := Map(LifecycleAntigravityPostTool, AgentAntigravity, model.AgentAntigravity, "event-2", payload)
	if ev.EventType != model.EventToolResult || ev.ToolName != "" {
		t.Errorf("event = %+v", ev)
	}
	if ev.ToolCallID != "step:7" {
		t.Errorf("tool_call_id = %q", ev.ToolCallID)
	}
	if !hasTag(ev.Tags, model.TagToolError) {
		t.Errorf("tags = %v, want tool_error", ev.Tags)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestResolveAntigravityLifecycle(t *testing.T) {
	tests := map[string]Lifecycle{
		"PreToolUse":            LifecycleAntigravityPreTool,
		"POSTTOOLUSE":           LifecycleAntigravityPostTool,
		"antigravity-pre-tool":  LifecycleAntigravityPreTool,
		"antigravity-post-tool": LifecycleAntigravityPostTool,
		"Stop":                  LifecycleStop,
	}
	for input, want := range tests {
		got, err := ResolveLifecycle(AgentAntigravity, input)
		if err != nil || got != want {
			t.Errorf("ResolveLifecycle(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"PreInvocation", "PostInvocation", "UserPromptSubmit", "BeforeTool", ""} {
		if _, err := ResolveLifecycle(AgentAntigravity, input); err == nil {
			t.Errorf("ResolveLifecycle(%q) succeeded", input)
		}
	}
}

func TestAntigravityInstallerResolverLifecycleParity(t *testing.T) {
	for _, event := range antigravityHookEvents {
		fromArg, argErr := ResolveLifecycle(AgentAntigravity, event.lifecycle)
		fromName, nameErr := ResolveLifecycle(AgentAntigravity, event.eventKey)
		if argErr != nil || nameErr != nil || fromArg != fromName {
			t.Errorf("event %q lifecycle %q: arg=%q/%v name=%q/%v", event.eventKey, event.lifecycle, fromArg, argErr, fromName, nameErr)
		}
	}
}
