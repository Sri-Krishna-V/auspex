package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func grokPayload(event, tool string, input map[string]any) map[string]any {
	payload := map[string]any{
		"hookEventName": event,
		"sessionId":     "session-1",
		"cwd":           "/workspace/project",
	}
	if tool != "" {
		payload["toolName"] = tool
		payload["toolInput"] = input
	}
	return payload
}

func TestMapGrokDocumentedTools(t *testing.T) {
	tests := []struct {
		name        string
		tool        string
		input       map[string]any
		wantType    model.EventType
		wantCommand string
		wantFile    string
		wantURL     string
	}{
		{name: "command", tool: "Bash", input: map[string]any{"command": "git status"}, wantType: model.EventCommandExec, wantCommand: "git status"},
		{name: "read", tool: "Read", input: map[string]any{"file_path": "/workspace/project/.env"}, wantType: model.EventFileRead, wantFile: "/workspace/project/.env"},
		{name: "write", tool: "Edit", input: map[string]any{"file_path": "/workspace/project/main.go"}, wantType: model.EventFileWrite, wantFile: "/workspace/project/main.go"},
		{name: "fetch", tool: "WebFetch", input: map[string]any{"url": "https://example.com/a"}, wantType: model.EventNetworkIndicator, wantURL: "https://example.com/a"},
		{name: "unknown", tool: "future_tool", input: map[string]any{}, wantType: model.EventToolCall},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(LifecycleGrokPreTool, AgentGrok, model.AgentGrok, "event-1", grokPayload("PreToolUse", tc.tool, tc.input))
			if ev.EventType != tc.wantType || ev.Command != tc.wantCommand || ev.FilePath != tc.wantFile || ev.URL != tc.wantURL {
				t.Errorf("event = %+v", ev)
			}
			if ev.SessionID != "session-1" || ev.ProjectPath != "/workspace/project" {
				t.Errorf("session/project = %q/%q", ev.SessionID, ev.ProjectPath)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

func TestMapGrokPostToolAndMCP(t *testing.T) {
	post := Map(LifecycleGrokPostTool, AgentGrok, model.AgentGrok, "event-2", grokPayload("PostToolUse", "Bash", map[string]any{"command": "false"}))
	if post.EventType != model.EventCommandResult || post.Command != "false" {
		t.Errorf("post = %+v", post)
	}
	if post.ExitCode != nil || post.DurationMs != nil {
		t.Errorf("undocumented result metadata populated: %+v", post)
	}

	failed := Map(LifecycleGrokPostTool, AgentGrok, model.AgentGrok, "event-3", grokPayload("PostToolUseFailure", "Edit", nil))
	if !hasTag(failed.Tags, model.TagToolError) {
		t.Errorf("failure tags = %v", failed.Tags)
	}

	for _, name := range []string{"github__create_issue", "mcp__github__create_issue"} {
		ev := Map(LifecycleGrokPreTool, AgentGrok, model.AgentGrok, "event-4", grokPayload("PreToolUse", name, nil))
		if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
			t.Errorf("%q split = %q/%q", name, ev.MCPServer, ev.MCPTool)
		}
	}
}

func TestResolveGrokLifecycle(t *testing.T) {
	tests := map[string]Lifecycle{
		"SessionStart":       LifecycleSessionStart,
		"UserPromptSubmit":   LifecyclePromptSubmit,
		"PreToolUse":         LifecycleGrokPreTool,
		"PostToolUse":        LifecycleGrokPostTool,
		"PostToolUseFailure": LifecycleGrokPostTool,
		"PermissionDenied":   LifecyclePermissionDenied,
		"SubagentStart":      LifecycleSessionStart,
		"SubagentStop":       LifecycleSessionEnd,
		"Stop":               LifecycleStop,
		"SessionEnd":         LifecycleSessionEnd,
	}
	for input, want := range tests {
		got, err := ResolveLifecycle(AgentGrok, input)
		if err != nil || got != want {
			t.Errorf("ResolveLifecycle(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"StopFailure", "PreCompact", "PermissionRequest", ""} {
		if _, err := ResolveLifecycle(AgentGrok, input); err == nil {
			t.Errorf("ResolveLifecycle(%q) succeeded", input)
		}
	}
}

func TestGrokInstallerResolverLifecycleParity(t *testing.T) {
	for _, event := range grokHookEvents {
		fromArg, argErr := ResolveLifecycle(AgentGrok, event.lifecycle)
		fromName, nameErr := ResolveLifecycle(AgentGrok, event.eventKey)
		if argErr != nil || nameErr != nil || fromArg != fromName {
			t.Errorf("event %q lifecycle %q: arg=%q/%v name=%q/%v", event.eventKey, event.lifecycle, fromArg, argErr, fromName, nameErr)
		}
	}
}

func readGrokTop(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return top
}

func readGrokHooks(t *testing.T, path string) grokHooks {
	t.Helper()
	var hooks grokHooks
	if err := json.Unmarshal(readGrokTop(t, path)["hooks"], &hooks); err != nil {
		t.Fatalf("parse hooks: %v", err)
	}
	return hooks
}

func TestGrokInstallWritesDocumentedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".grok", "hooks", grokManagedFile)
	rep, err := Install(AgentGrok, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v", rep)
	}
	top := readGrokTop(t, path)
	if len(top) != 1 || top["hooks"] == nil {
		t.Fatalf("top-level keys = %v, want only hooks", topKeys(top))
	}
	hooks := readGrokHooks(t, path)
	if len(hooks) != len(grokHookEvents) {
		t.Fatalf("hook events = %d, want %d", len(hooks), len(grokHookEvents))
	}
	for _, event := range grokHookEvents {
		groups := hooks[event.eventKey]
		if len(groups) != 1 || groups[0].Matcher != "" || len(groups[0].Hooks) != 1 {
			t.Fatalf("%s groups = %+v", event.eventKey, groups)
		}
		cmd := groups[0].Hooks[0].Command
		command := hookCommandText(cmd)
		if !strings.Contains(command, auspexHookMarker) || !strings.Contains(command, "--agent grok") || strings.Contains(command, "--enforce") {
			t.Errorf("%s command = %q", event.eventKey, cmd)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !modeMatches(info.Mode().Perm(), 0o600) {
		t.Errorf("mode = %o", info.Mode().Perm())
	}
}

func TestGrokInstallIsIdempotentAndWiresOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks", grokManagedFile)
	const out = "/home/u/.auspex/events.ndjson"
	if _, err := Install(AgentGrok, path, auspexBinary, out, false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := readGrokHooks(t, path)["PreToolUse"][0].Hooks[0].Command
	if command := hookCommandText(cmd); !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
		t.Errorf("command missing output args: %q", cmd)
	}
	if _, err := Install(AgentGrok, path, auspexBinary, out, false); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("reinstall changed output")
	}
}

func TestGrokInstallPreservesForeignGroupsInOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks", grokManagedFile)
	if _, err := Install(AgentGrok, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	hooks := readGrokHooks(t, path)
	hooks["PreToolUse"] = append(hooks["PreToolUse"], hookGroup{Matcher: "Read", Hooks: []hookRef{{Command: "echo foreign"}}})
	raw, err := json.Marshal(map[string]any{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentGrok, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	if groups := readGrokHooks(t, path)["PreToolUse"]; len(groups) != 2 || groups[0].Hooks[0].Command != "echo foreign" {
		t.Errorf("groups after reinstall = %+v", groups)
	}
	if _, err := Uninstall(AgentGrok, path); err != nil {
		t.Fatal(err)
	}
	groups := readGrokHooks(t, path)["PreToolUse"]
	if len(groups) != 1 || groups[0].Hooks[0].Command != "echo foreign" {
		t.Errorf("groups after uninstall = %+v", groups)
	}
}

func TestGrokInstallRefusesForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks", grokManagedFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const original = `{"hooks":{"PreToolUse":[{"hooks":[{"command":"echo user"}]}]}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentGrok, path, auspexBinary, "", false); err == nil {
		t.Fatal("Install succeeded over a foreign file")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("foreign file changed: %s", got)
	}
}

func TestGrokUninstallRemovesOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks", grokManagedFile)
	if _, err := Install(AgentGrok, path, "/opt/tools/agent-watch", "", false); err != nil {
		t.Fatal(err)
	}
	if !Status(AgentGrok, path).Installed {
		t.Fatal("status did not recognize marker-bearing commands")
	}
	if _, err := Uninstall(AgentGrok, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("owned file remains: %v", err)
	}
}

func TestGrokProjectScopeTrustNote(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("GROK_HOME", "")
	projectPath := filepath.Join(t.TempDir(), ".grok", "hooks", grokManagedFile)
	rep, err := Install(AgentGrok, projectPath, auspexBinary, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.Message, "/hooks-trust") {
		t.Errorf("project install message = %q", rep.Message)
	}

	userPath := GrokHooksPath(home)
	rep, err = Install(AgentGrok, userPath, auspexBinary, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rep.Message, "/hooks-trust") {
		t.Errorf("user install message = %q", rep.Message)
	}
}

func TestGrokPathAndEnforce(t *testing.T) {
	t.Setenv("GROK_HOME", "")
	want := filepath.Join("/home/u", ".grok", "hooks", "auspex.json")
	if got := GrokHooksPath("/home/u"); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	path := filepath.Join(t.TempDir(), "hooks", grokManagedFile)
	if _, err := Install(AgentGrok, path, auspexBinary, "", true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(hookCommandText(string(data)), enforceFlag); got != 1 {
		t.Fatalf("enforce flags = %d, want 1 in PreToolUse only\n%s", got, data)
	}
}

func TestGrokHomeOverrideIsUserScope(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	root := filepath.Join(t.TempDir(), "relocated grok")
	t.Setenv("GROK_HOME", root)

	want := filepath.Join(root, "hooks", grokManagedFile)
	if got := GrokHooksPath(home); got != want {
		t.Fatalf("GrokHooksPath = %q, want %q", got, want)
	}
	rep, err := Install(AgentGrok, want, auspexBinary, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rep.Message, "/hooks-trust") {
		t.Errorf("relocated user install was classified as project scope: %q", rep.Message)
	}
}
