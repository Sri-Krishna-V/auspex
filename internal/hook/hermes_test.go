package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
	"go.yaml.in/yaml/v3"
)

// hrm builds Hermes's documented shell-hook envelope.
func hrm(toolName string, extra map[string]any) map[string]any {
	p := map[string]any{}
	if toolName != "" {
		p["tool_name"] = toolName
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestMapHermesDocumentedToolEvents(t *testing.T) {
	cases := []struct {
		name  string
		lc    Lifecycle
		tool  string
		input map[string]any
		extra map[string]any
		want  model.EventType
		check func(*testing.T, model.Event)
	}{
		{
			name: "terminal pre", lc: LifecycleHermesPreTool, tool: "terminal",
			input: map[string]any{"command": "go test ./..."}, want: model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "go test ./..." {
					t.Errorf("command = %q", ev.Command)
				}
			},
		},
		{
			name: "terminal post", lc: LifecycleHermesPostTool, tool: "terminal",
			input: map[string]any{"command": "false"},
			extra: map[string]any{"duration_ms": float64(12), "status": "error", "error_message": "failed", "tool_call_id": "call-1"},
			want:  model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.DurationMs == nil || *ev.DurationMs != 12 {
					t.Errorf("duration_ms = %v, want 12", ev.DurationMs)
				}
				if ev.ToolCallID != "call-1" || !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tool result metadata = %+v", ev)
				}
			},
		},
		{
			name: "read", lc: LifecycleHermesPreTool, tool: "read_file",
			input: map[string]any{"path": "/repo/.env"}, want: model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/repo/.env" {
					t.Errorf("file_path = %q", ev.FilePath)
				}
			},
		},
		{
			name: "patch", lc: LifecycleHermesPreTool, tool: "patch",
			input: map[string]any{"path": "/repo/main.go"}, want: model.EventFileWrite,
		},
		{
			name: "web search", lc: LifecycleHermesPreTool, tool: "web_search",
			input: map[string]any{"query": "Go release notes"}, want: model.EventNetworkIndicator,
		},
		{
			name: "web extract", lc: LifecycleHermesPreTool, tool: "web_extract",
			input: map[string]any{"url": "https://go.dev/doc"}, want: model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "https://go.dev/doc" {
					t.Errorf("url = %q", ev.URL)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := hrm(c.tool, map[string]any{"tool_input": c.input, "extra": c.extra})
			ev := Map(c.lc, AgentHermes, model.AgentHermesCLI, "e", payload)
			if ev.EventType != c.want {
				t.Errorf("event_type = %q, want %q", ev.EventType, c.want)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped hermes event failed Validate: %v", err)
			}
			if c.check != nil {
				c.check(t, ev)
			}
		})
	}
}

func TestMapHermesDocumentedLifecycleEnvelope(t *testing.T) {
	cases := []struct {
		name    string
		lc      Lifecycle
		payload map[string]any
		want    model.EventType
		check   func(*testing.T, model.Event)
	}{
		{
			name: "session start model in extra",
			lc:   LifecycleSessionStart,
			payload: map[string]any{
				"hook_event_name": "on_session_start", "session_id": "session-1", "cwd": "/repo",
				"extra": map[string]any{"model": "hermes-model", "platform": "cli"},
			},
			want: model.EventSessionStart,
			check: func(t *testing.T, ev model.Event) {
				if ev.SessionID != "session-1" || ev.ProjectPath != "/repo" || ev.Model != "hermes-model" {
					t.Errorf("session start = %+v", ev)
				}
			},
		},
		{
			name: "prompt text in extra",
			lc:   LifecyclePromptSubmit,
			payload: map[string]any{
				"hook_event_name": "pre_llm_call", "session_id": "session-1", "cwd": "/repo",
				"extra": map[string]any{"user_message": "  inspect   the diff  "},
			},
			want: model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.ContentPreview != "inspect the diff" {
					t.Errorf("content_preview = %q", ev.ContentPreview)
				}
			},
		},
		{
			name: "subagent start uses child identity",
			lc:   LifecycleSessionStart,
			payload: map[string]any{
				"hook_event_name": "subagent_start", "session_id": "parent-session", "cwd": "/repo",
				"extra": map[string]any{"child_session_id": "child-session", "child_role": "reviewer", "parent_turn_id": "turn-1"},
			},
			want: model.EventSessionStart,
			check: func(t *testing.T, ev model.Event) {
				if ev.SessionID != "child-session" || ev.SubAgent != "reviewer" {
					t.Errorf("subagent start = %+v", ev)
				}
			},
		},
		{
			name: "subagent stop uses child identity",
			lc:   LifecycleSessionEnd,
			payload: map[string]any{
				"hook_event_name": "subagent_stop", "session_id": "parent-session", "cwd": "/repo",
				"extra": map[string]any{"child_session_id": "child-session", "child_role": "reviewer", "child_status": "completed"},
			},
			want: model.EventSessionEnd,
			check: func(t *testing.T, ev model.Event) {
				if ev.SessionID != "child-session" || ev.SubAgent != "reviewer" {
					t.Errorf("subagent stop = %+v", ev)
				}
			},
		},
		{
			name: "finalize keeps outgoing identity",
			lc:   LifecycleSessionEnd,
			payload: map[string]any{
				"hook_event_name": "on_session_finalize", "session_id": "outgoing-session", "cwd": "/repo",
				"extra": map[string]any{"platform": "telegram"},
			},
			want: model.EventSessionEnd,
			check: func(t *testing.T, ev model.Event) {
				if ev.SessionID != "outgoing-session" {
					t.Errorf("finalize session_id = %q", ev.SessionID)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(tc.lc, AgentHermes, model.AgentHermesCLI, "event-1", tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			tc.check(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

func TestHermesPostToolStatusIsAuthoritative(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]any
		want  bool
	}{
		{"explicit error status", map[string]any{"status": "error"}, true},
		{"explicit error type", map[string]any{"error_type": "ValueError"}, true},
		{"ok result may contain error data", map[string]any{"status": "ok", "result": `{"error":"domain value"}`}, false},
		{"blocked is not an execution error", map[string]any{"status": "blocked", "error_message": "blocked by policy"}, false},
		{"legacy result fallback", map[string]any{"result": `{"error":"failed"}`}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := hrm("web_extract", map[string]any{
				"hook_event_name": "post_tool_call",
				"tool_input":      map[string]any{"url": "https://example.com"},
				"extra":           tc.extra,
			})
			ev := Map(LifecycleHermesPostTool, AgentHermes, model.AgentHermesCLI, "event-1", payload)
			if got := hasTag(ev.Tags, model.TagToolError); got != tc.want {
				t.Errorf("tool_error = %t, want %t; event = %+v", got, tc.want, ev)
			}
		})
	}
}

func TestHermesDenyResponseUsesCanonicalShape(t *testing.T) {
	got, ok := DenyResponse(AgentHermes, "blocked by policy")
	if !ok || got["action"] != "block" || got["message"] != "blocked by policy" {
		t.Fatalf("deny response = %#v, %t", got, ok)
	}
}

// TestMapHermesPreToolIsToolCall confirms the pre moment is a tool.call with the tool
// name and MCP split, and no fabricated result metadata.
func TestMapHermesPreToolIsToolCall(t *testing.T) {
	ev := Map(LifecycleHermesPreTool, AgentHermes, model.AgentHermesCLI, "e", hrm("mcp__srv__do", map[string]any{"code": float64(2)}))
	if ev.EventType != model.EventToolCall {
		t.Errorf("event_type = %q, want tool.call", ev.EventType)
	}
	if ev.ToolName != "mcp__srv__do" {
		t.Errorf("tool_name = %q, want mcp__srv__do", ev.ToolName)
	}
	if ev.MCPServer != "srv" || ev.MCPTool != "do" {
		t.Errorf("mcp split = %q/%q, want srv/do", ev.MCPServer, ev.MCPTool)
	}
	if ev.ExitCode != nil {
		t.Errorf("exit_code = %v, want nil (no fabrication on pre moment)", *ev.ExitCode)
	}
	assertHookProvenance(t, ev)
	if err := ev.Validate(); err != nil {
		t.Errorf("mapped hermes pre event failed Validate: %v", err)
	}
}

func TestMapHermesApprovalEvents(t *testing.T) {
	payload := map[string]any{
		"decision": "denied",
		"extra": map[string]any{
			"command":     "rm -rf build",
			"description": "destructive command",
			"session_key": "session-1",
		},
	}
	request := Map(LifecycleHermesPermission, AgentHermes, model.AgentHermesCLI, "request", payload)
	if request.EventType != model.EventPermissionRequested || request.Decision != model.DecisionAsked {
		t.Fatalf("request = %+v", request)
	}
	if request.ApprovalReason != "destructive command" {
		t.Errorf("approval_reason = %q", request.ApprovalReason)
	}
	if request.SessionID != "session-1" {
		t.Errorf("approval correlation = %+v", request)
	}

	for _, tc := range []struct {
		choice string
		want   model.EventType
		dec    string
	}{
		{"once", model.EventPermissionApproved, model.DecisionAllowed},
		{"smart_approve", model.EventPermissionApproved, model.DecisionAllowed},
		{"deny", model.EventPermissionDenied, model.DecisionDenied},
		{"timeout", model.EventPermissionDenied, model.DecisionDenied},
	} {
		t.Run(tc.choice, func(t *testing.T) {
			ev := Map(LifecycleHermesPermissionResult, AgentHermes, model.AgentHermesCLI, tc.choice, map[string]any{
				"extra": map[string]any{"choice": tc.choice, "description": "destructive command", "command": "rm -rf build", "session_key": "session-1"},
			})
			if ev.EventType != tc.want || ev.Decision != tc.dec || ev.ApprovalDecision != tc.dec {
				t.Errorf("approval result = %+v", ev)
			}
			if ev.SessionID != "session-1" {
				t.Errorf("approval correlation = %+v", ev)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

// TestResolveHermesLifecycle asserts the raw Hermes event names AND the auspex lifecycle
// args resolve, while a near-miss is rejected (unknown-event → exit 2 upstream).
func TestResolveHermesLifecycle(t *testing.T) {
	cases := []struct {
		raw  string
		want Lifecycle
		ok   bool
	}{
		{"on_session_start", LifecycleSessionStart, true},
		{"pre_llm_call", LifecyclePromptSubmit, true},
		{"post_llm_call", LifecycleAssistant, true},
		{"pre_tool_call", LifecycleHermesPreTool, true},
		{"post_tool_call", LifecycleHermesPostTool, true},
		{"pre_approval_request", LifecycleHermesPermission, true},
		{"post_approval_response", LifecycleHermesPermissionResult, true},
		{"subagent_start", LifecycleSessionStart, true},
		{"subagent_stop", LifecycleSessionEnd, true},
		{"on_session_finalize", LifecycleSessionEnd, true},
		// Case-folded acceptance.
		{"PRE_TOOL_CALL", LifecycleHermesPreTool, true},
		// auspex lifecycle args pass straight through.
		{string(LifecycleHermesPreTool), LifecycleHermesPreTool, true},
		{string(LifecycleHermesPostTool), LifecycleHermesPostTool, true},
		{string(LifecycleHermesPermission), LifecycleHermesPermission, true},
		{string(LifecycleHermesPermissionResult), LifecycleHermesPermissionResult, true},
		{string(LifecycleAssistant), LifecycleAssistant, true},
		{string(LifecycleSessionStart), LifecycleSessionStart, true},
		{string(LifecyclePromptSubmit), LifecyclePromptSubmit, true},
		{string(LifecycleSessionEnd), LifecycleSessionEnd, true},
		// Near-miss rejected, not substring-matched.
		{"pre_tool", "", false},
		{"session_start", "", false},
		{"approval_request", "", false},
		{"on_session_end", "", false},
		{"on_session_reset", "", false},
		{"pre_verify", "", false},
		{"pre_gateway_dispatch", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, ok := resolveHermesEvent(c.raw)
			if ok != c.ok || got != c.want {
				t.Errorf("resolveHermesEvent(%q) = (%q,%v), want (%q,%v)", c.raw, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestHermesInstallerResolverLifecycleParity guards against installer/runtime drift:
// every lifecycle arg the installer writes must resolve back through ResolveLifecycle.
func TestHermesInstallerResolverLifecycleParity(t *testing.T) {
	for _, lc := range HermesLifecycleArgs() {
		got, err := ResolveLifecycle(AgentHermes, lc)
		if err != nil {
			t.Errorf("installer writes lifecycle %q that the resolver rejects: %v", lc, err)
			continue
		}
		if string(got) != lc {
			t.Errorf("lifecycle %q resolved to %q (installer/runtime drift)", lc, got)
		}
	}
}

// hermesUserPath returns a user-scope config path inside an isolated HOME so the
// user-scope guard accepts it.
func hermesUserPath(t *testing.T) (home, path string) {
	t.Helper()
	home = t.TempDir()
	setTestHome(t, home)
	t.Setenv("HERMES_HOME", "")
	return home, HermesUserConfigPath(home)
}

func TestHermesUserConfigPathHonorsHermesHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HERMES_HOME", root)
	if got, want := HermesUserConfigPath("/home/u"), filepath.Join(root, "config.yaml"); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// readHermesTop parses a Hermes config back into a top-level map for assertions.
func readHermesTop(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var top map[string]any
	if err := yaml.Unmarshal(data, &top); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return top
}

func TestHermesInstallWritesMappedEvents(t *testing.T) {
	_, path := hermesUserPath(t)
	rep, err := installHermesWithArgs(path, "/opt/auspex", nil, false)
	if err != nil {
		t.Fatalf("installHermes: %v", err)
	}
	if !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want installed+changed", rep)
	}
	hf, err := readHermesFile(path)
	if err != nil {
		t.Fatalf("readHermesFile: %v", err)
	}
	if len(hf.hooks) != len(hermesHookEvents) {
		t.Errorf("wired %d events, want %d", len(hf.hooks), len(hermesHookEvents))
	}
	for _, ev := range hermesHookEvents {
		refs := hf.hooks[ev.eventKey]
		if len(refs) != 1 {
			t.Errorf("event %q: %d refs, want 1", ev.eventKey, len(refs))
			continue
		}
		ref := refs[0]
		command := hookCommandText(ref.Command)
		if !isAuspexHookCommand(ref.Command) {
			t.Errorf("event %q: command %q missing auspex marker", ev.eventKey, ref.Command)
		}
		if !strings.Contains(command, "--agent hermes") {
			t.Errorf("event %q: command %q missing --agent hermes", ev.eventKey, ref.Command)
		}
		if !strings.Contains(command, ev.lifecycle) {
			t.Errorf("event %q: command %q missing lifecycle %q", ev.eventKey, ref.Command, ev.lifecycle)
		}
		if ref.Matcher != "" {
			t.Errorf("event %q: matcher %q, want omitted", ev.eventKey, ref.Matcher)
		}
		if ref.Timeout != ev.timeout {
			t.Errorf("event %q: timeout %d, want %d", ev.eventKey, ref.Timeout, ev.timeout)
		}
	}
	// Omitted matchers cover every tool.
	if hf.hooks["pre_tool_call"][0].Matcher != "" || hf.hooks["post_tool_call"][0].Matcher != "" {
		t.Errorf("tool matchers must be omitted")
	}
	if hf.hooks["pre_approval_request"][0].Matcher != "" {
		t.Errorf("approval moment must omit matcher")
	}
}

func TestHermesInstallIsIdempotent(t *testing.T) {
	_, path := hermesUserPath(t)
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hf, err := readHermesFile(path)
	if err != nil {
		t.Fatalf("readHermesFile: %v", err)
	}
	for _, ev := range hermesHookEvents {
		if got := len(hf.hooks[ev.eventKey]); got != 1 {
			t.Errorf("event %q: %d refs after reinstall, want 1 (idempotent)", ev.eventKey, got)
		}
	}
}

func TestHermesInstallWiresDurableOutputFile(t *testing.T) {
	_, path := hermesUserPath(t)
	if _, err := installHermesWithArgs(path, "/opt/auspex", outputFileArgs("/var/findings.jsonl"), false); err != nil {
		t.Fatalf("installHermes: %v", err)
	}
	hf, _ := readHermesFile(path)
	cmd := hf.hooks["on_session_start"][0].Command
	if command := hookCommandText(cmd); !strings.Contains(command, "--output=file") || !strings.Contains(command, "/var/findings.jsonl") {
		t.Errorf("command missing durable output wiring: %q", cmd)
	}
}

// TestHermesInstallPreservesForeignContent: a foreign top-level key AND a foreign hook
// ref both survive install and uninstall, and only auspex's content is added/removed.
func TestHermesInstallPreservesForeignContent(t *testing.T) {
	_, path := hermesUserPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const seeded = "model: gpt-5\n" +
		"hooks:\n" +
		"  pre_tool_call:\n" +
		"    - command: echo foreign\n" +
		"      matcher: \".*\"\n"
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	top := readHermesTop(t, path)
	if top["model"] != "gpt-5" {
		t.Errorf("foreign top-level key dropped on install; top = %v", top)
	}
	hf, _ := readHermesFile(path)
	// pre_tool_call must now hold the foreign ref AND auspex's ref.
	var foreignSeen, auspexSeen bool
	for _, ref := range hf.hooks["pre_tool_call"] {
		if strings.Contains(ref.Command, "echo foreign") {
			foreignSeen = true
		}
		if isAuspexHookCommand(ref.Command) {
			auspexSeen = true
		}
	}
	if !foreignSeen || !auspexSeen {
		t.Errorf("pre_tool_call refs = %+v, want both foreign and auspex", hf.hooks["pre_tool_call"])
	}
	// Uninstall must strip only auspex's refs and leave the foreign content.
	if _, err := uninstallHermes(path); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	top = readHermesTop(t, path)
	if top["model"] != "gpt-5" {
		t.Fatalf("foreign top-level key removed on uninstall; top = %v", top)
	}
	hf, _ = readHermesFile(path)
	if hasAuspexRef(hf.hooks["pre_tool_call"]) {
		t.Errorf("auspex ref survived uninstall: %+v", hf.hooks["pre_tool_call"])
	}
	var stillForeign bool
	for _, ref := range hf.hooks["pre_tool_call"] {
		if strings.Contains(ref.Command, "echo foreign") {
			stillForeign = true
		}
	}
	if !stillForeign {
		t.Errorf("foreign hook ref dropped on uninstall: %+v", hf.hooks["pre_tool_call"])
	}
}

func TestHermesInstallRejectsDuplicateHooksKey(t *testing.T) {
	_, path := hermesUserPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const seeded = "hooks:\n  pre_tool_call: []\nhooks:\n  post_tool_call: []\n"
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err == nil || !strings.Contains(err.Error(), "duplicate top-level hooks key") {
		t.Fatalf("install error = %v, want duplicate-hooks error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after rejected install: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected install modified the config")
	}
}

// hermesRootKeys parses the raw bytes at path into a yaml.Node and returns the ordered
// list of top-level keys plus the root mapping node, so tests can observe ORDER and
// node-level types (not just a map). It fails the test if the file is not a top-level map.
func hermesRootKeys(t *testing.T, path string) ([]string, *yaml.Node) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse node %s: %v", path, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		t.Fatalf("empty document %s", path)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		t.Fatalf("top-level YAML is not a map in %s", path)
	}
	var keys []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		keys = append(keys, root.Content[i].Value)
	}
	return keys, root
}

// hermesRootValue returns the value node for a top-level key from a root mapping node, or
// nil if the key is absent.
func hermesRootValue(root *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1]
		}
	}
	return nil
}

// TestHermesInstallPreservesTopLevelKeyOrderAndNodes verifies that auspex
// changes only the hooks node in a commented, deliberately ordered config.
func TestHermesInstallPreservesTopLevelKeyOrderAndNodes(t *testing.T) {
	_, path := hermesUserPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// No original hooks key; foreign values span scalar, map, and sequence nodes.
	const seeded = "# head comment\n" +
		"zeta: 1\n" +
		"model: gpt-5        # inline comment\n" +
		"alpha:\n" +
		"  nested: true\n" +
		"beta: [a, b, c]\n"
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatalf("install: %v", err)
	}

	keys, root := hermesRootKeys(t, path)
	wantForeignOrder := []string{"zeta", "model", "alpha", "beta"}
	var gotForeign []string
	var hooksSeen bool
	for _, k := range keys {
		if k == "hooks" {
			hooksSeen = true
			continue
		}
		gotForeign = append(gotForeign, k)
	}
	if !equalStrings(gotForeign, wantForeignOrder) {
		t.Errorf("foreign top-level order = %v, want %v (original order must survive, not be sorted)", gotForeign, wantForeignOrder)
	}
	if !hooksSeen {
		t.Fatalf("hooks key not added on install; keys = %v", keys)
	}
	hf, _ := readHermesFile(path)
	if len(hf.hooks) != len(hermesHookEvents) {
		t.Errorf("wired %d events, want %d", len(hf.hooks), len(hermesHookEvents))
	}

	if v := hermesRootValue(root, "alpha"); v == nil || v.Kind != yaml.MappingNode {
		t.Errorf("alpha must remain a map node, got %+v", v)
	}
	if v := hermesRootValue(root, "beta"); v == nil || v.Kind != yaml.SequenceNode {
		t.Errorf("beta must remain a sequence node, got %+v", v)
	}
	if v := hermesRootValue(root, "zeta"); v == nil || v.Kind != yaml.ScalarNode || v.Tag != "!!int" || v.Value != "1" {
		t.Errorf("zeta must remain int 1, got %+v", v)
	}
	if v := hermesRootValue(root, "model"); v == nil || v.Kind != yaml.ScalarNode || v.Value != "gpt-5" {
		t.Errorf("model must remain string gpt-5, got %+v", v)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	if !strings.Contains(string(raw), "# inline comment") && !strings.Contains(string(raw), "# head comment") {
		t.Errorf("expected a foreign comment (# inline comment or # head comment) to survive; file:\n%s", raw)
	}

	// Uninstall: foreign keys + order still survive; hooks key gone; file not removed.
	if _, err := uninstallHermes(path); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	keys, _ = hermesRootKeys(t, path)
	var gotForeign2 []string
	for _, k := range keys {
		if k == "hooks" {
			t.Errorf("hooks key must be gone after uninstall; keys = %v", keys)
			continue
		}
		gotForeign2 = append(gotForeign2, k)
	}
	if !equalStrings(gotForeign2, wantForeignOrder) {
		t.Errorf("foreign order after uninstall = %v, want %v", gotForeign2, wantForeignOrder)
	}
}

// equalStrings reports whether two string slices are element-wise equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestHermesUninstallRemovesEmptiedFile: when auspex was the only content, an uninstall
// removes the file rather than leaving a bare object.
func TestHermesUninstallRemovesEmptiedFile(t *testing.T) {
	_, path := hermesUserPath(t)
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := uninstallHermes(path); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should be removed when emptied; stat err = %v", err)
	}
}

// TestHermesProjectScopeRefused: a project-level path is rejected with a clear error and
// writes nothing.
func TestHermesProjectScopeRefused(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	proj := filepath.Join(t.TempDir(), "proj", ".hermes", "config.yaml")
	rep, err := installHermesWithArgs(proj, "/opt/auspex", nil, false)
	if err == nil {
		t.Fatalf("expected project-scope install to be refused, got rep = %+v", rep)
	}
	if !strings.Contains(err.Error(), "user config") {
		t.Errorf("error = %q, want a user-config-only message", err.Error())
	}
	if _, statErr := os.Stat(proj); !os.IsNotExist(statErr) {
		t.Errorf("project install must write NOTHING; file exists (stat err = %v)", statErr)
	}
}

func TestHermesEnforceInstallThreadsOnlyPreTool(t *testing.T) {
	_, path := hermesUserPath(t)
	if _, err := Install(AgentHermes, path, "/opt/auspex", "", true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(hookCommandText(string(data)), enforceFlag); got != 1 {
		t.Fatalf("enforce flags = %d, want 1 in pre_tool_call only\n%s", got, data)
	}
}

func TestHermesUserConfigPathPlatforms(t *testing.T) {
	tests := []struct {
		name, home, goos, localAppData, hermesHome, want string
	}{
		{"unix default", "/home/u", "linux", "", "", filepath.Join("/home/u", ".hermes", "config.yaml")},
		{"override", "/home/u", "windows", `C:\Local`, `D:\Hermes`, filepath.Join(`D:\Hermes`, "config.yaml")},
		{"windows localappdata", `C:\Users\u`, "windows", `C:\Users\u\AppData\Local`, "", filepath.Join(`C:\Users\u\AppData\Local`, "hermes", "config.yaml")},
		{"windows fallback", `C:\Users\u`, "windows", "", "", filepath.Join(`C:\Users\u`, "AppData", "Local", "hermes", "config.yaml")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hermesUserConfigPath(tc.home, tc.goos, tc.localAppData, tc.hermesHome); got != tc.want {
				t.Fatalf("path = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHermesDetectionIsRenameProof: a binary renamed away from "auspex" still produces a
// command carrying the marker, so status detects it.
func TestHermesDetectionIsRenameProof(t *testing.T) {
	_, path := hermesUserPath(t)
	if _, err := installHermesWithArgs(path, "/opt/renamed-tool", nil, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !statusHermes(path).Installed {
		t.Errorf("status should detect auspex hooks regardless of binary name")
	}
}

// TestHermesUninstallNoFileIsNoOp: uninstalling when no file exists is a clean no-op.
func TestHermesUninstallNoFileIsNoOp(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	path := HermesUserConfigPath(home)
	rep, err := uninstallHermes(path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if rep.Changed {
		t.Errorf("uninstall of missing file should be a no-op, got Changed=true")
	}
}

// TestHermesStatusReflectsInstallState round-trips status across install/uninstall.
func TestHermesStatusReflectsInstallState(t *testing.T) {
	_, path := hermesUserPath(t)
	if statusHermes(path).Installed {
		t.Errorf("status before install should be not-installed")
	}
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !statusHermes(path).Installed {
		t.Errorf("status after install should be installed")
	}
	hf, err := readHermesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	delete(hf.hooks, "on_session_finalize")
	if err := writeHermesFile(path, hf); err != nil {
		t.Fatal(err)
	}
	if rep := statusHermes(path); rep.Installed || !strings.Contains(rep.Message, "partial") {
		t.Fatalf("partial status = %+v", rep)
	}
	if _, err := installHermesWithArgs(path, "/opt/auspex", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := uninstallHermes(path); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if statusHermes(path).Installed {
		t.Errorf("status after uninstall should be not-installed")
	}
}

// TestHermesParseAgentAndPassthrough confirms the --agent value maps to the model source
// id and the passthrough is the inert {}.
func TestHermesParseAgentAndPassthrough(t *testing.T) {
	src, err := ParseAgent(AgentHermes)
	if err != nil {
		t.Fatalf("ParseAgent: %v", err)
	}
	if src != model.AgentHermesCLI {
		t.Errorf("ParseAgent(hermes) = %q, want %q", src, model.AgentHermesCLI)
	}
	if got := PassthroughResponse(AgentHermes, LifecycleHermesPreTool); len(got) != 0 {
		t.Errorf("passthrough = %v, want empty {} (observe-only)", got)
	}
}
