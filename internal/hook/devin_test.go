package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// dvn builds a Devin CLI hook payload.
func dvn(toolName string, extra map[string]any) map[string]any {
	p := map[string]any{}
	if toolName != "" {
		p["tool_name"] = toolName
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// Generic top-level result keys are not part of Devin's documented tool payload.
// The Devin-specific mapper must ignore them.
func TestMapDevinPostToolNoFabricatedMetadata(t *testing.T) {
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
			// Devin's documented shell tool name is "exec", not "Bash".
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
			// Generic failure-looking keys must not override the documented shape.
			name: "failure-shape",
			tool: "Write",
			payload: map[string]any{
				"file_path": "/p/f",
				"diff":      "--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n",
				"is_error":  true,
				"error":     "tool blew up",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Map(LifecycleDevinPostTool, AgentDevin, model.AgentDevinCLI, "e", dvn(c.tool, c.payload))

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
				t.Errorf("mapped devin event failed Validate: %v", err)
			}
		})
	}
}

// The PreToolUse moment maps to tool.call (EventToolCall) and likewise fabricates no
// result metadata from generic fallback keys present in the payload.
func TestMapDevinPreToolNoFabricatedMetadata(t *testing.T) {
	pre := Map(LifecycleDevinPreTool, AgentDevin, model.AgentDevinCLI, "pre", dvn("Bash", map[string]any{
		"command":     "echo hi",
		"exit_code":   float64(1),
		"duration_ms": float64(9),
		"is_error":    true,
	}))
	if pre.EventType != model.EventToolCall {
		t.Errorf("pre event_type = %q, want tool.call", pre.EventType)
	}
	if pre.ToolName != "Bash" {
		t.Errorf("pre tool_name = %q, want Bash", pre.ToolName)
	}
	if pre.ExitCode != nil || pre.DurationMs != nil {
		t.Errorf("pre must carry no exit_code/duration_ms: %+v", pre)
	}
	if pre.DiffSHA256 != "" || pre.DiffBytes != 0 {
		t.Errorf("pre must carry no diff")
	}
	if hasTag(pre.Tags, model.TagToolError) {
		t.Errorf("pre tags = %v, want NO tool_error", pre.Tags)
	}
	assertHookProvenance(t, pre)
	if err := pre.Validate(); err != nil {
		t.Errorf("mapped devin pre event failed Validate: %v", err)
	}

	// An MCP-style tool name splits into MCPServer/MCPTool via the pure splitMCPName
	// parse (no fabrication); a non-MCP name leaves them empty.
	mcp := Map(LifecycleDevinPostTool, AgentDevin, model.AgentDevinCLI, "p2", dvn("mcp__github__create_issue", nil))
	if mcp.MCPServer != "github" || mcp.MCPTool != "create_issue" {
		t.Errorf("MCP split = %q/%q, want github/create_issue", mcp.MCPServer, mcp.MCPTool)
	}
}

// Devin's PermissionRequest input is pre-decision, so it records an open request.
func TestMapDevinPermissionRequestObserveOnly(t *testing.T) {
	lc, err := ResolveLifecycle(AgentDevin, "PermissionRequest")
	if err != nil {
		t.Fatalf("ResolveLifecycle(devin, PermissionRequest): %v", err)
	}
	if lc != LifecycleDevinPermission {
		t.Fatalf("PermissionRequest resolved to %q, want %q (observe-only Devin permission lifecycle)", lc, LifecycleDevinPermission)
	}
	ev := Map(lc, AgentDevin, model.AgentDevinCLI, "perm", dvn("Bash", map[string]any{"command": "rm -rf /"}))
	assertHookProvenance(t, ev)
	if ev.EventType != model.EventPermissionRequested {
		t.Errorf("event type = %q, want %q (observe-only)", ev.EventType, model.EventPermissionRequested)
	}
	if ev.Decision != model.DecisionAsked || ev.ApprovalDecision != model.DecisionAsked {
		t.Errorf("decision=%q approval=%q, want both %q", ev.Decision, ev.ApprovalDecision, model.DecisionAsked)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("mapped devin permission event failed Validate: %v", err)
	}
}

// ResolveLifecycle must map each Devin hook-event name auspex wires onto the right
// auspex lifecycle. The match is EXACT (case-folded): the two tool moments route to
// the Devin-specific lifecycles, PermissionRequest to the shared permission lifecycle,
// and (unlike Grok/Factory) Devin keeps a DISTINCT Stop→stop moment separate from
// SessionEnd→session-end. A near-miss surfaces as an unknown-event operator error.
func TestResolveDevinLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"SessionStart", LifecycleSessionStart},
		{"UserPromptSubmit", LifecyclePromptSubmit},
		{"PreToolUse", LifecycleDevinPreTool},
		{"PostToolUse", LifecycleDevinPostTool},
		{"PermissionRequest", LifecycleDevinPermission},
		{"Stop", LifecycleStop},
		{"SessionEnd", LifecycleSessionEnd},
		// Case-insensitivity on the label.
		{"pretooluse", LifecycleDevinPreTool},
		{"SESSIONSTART", LifecycleSessionStart},
		{"permissionrequest", LifecycleDevinPermission},
		// The auspex lifecycle-arg spellings the installer wires verbatim.
		{"devin-pre-tool", LifecycleDevinPreTool},
		{"devin-post-tool", LifecycleDevinPostTool},
		{"devin-permission-request", LifecycleDevinPermission},
		{"session-start", LifecycleSessionStart},
		{"prompt-submit", LifecyclePromptSubmit},
		{"stop", LifecycleStop},
		{"session-end", LifecycleSessionEnd},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentDevin, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(devin, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(devin, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	// A near-miss must error rather than being silently accepted.
	for _, bad := range []string{"PreToolUseV2", "PostToolUseFailure", "BeforeTool", "pre-tool", "post-tool", "permission-request", "PermissionRequested", ""} {
		if _, err := ResolveLifecycle(AgentDevin, bad); err == nil {
			t.Errorf("ResolveLifecycle(devin, %q) should error: not a wired Devin event", bad)
		}
	}
}

// Installer/runtime parity: for every event the installer wires (devinHookEvents), the
// runtime resolver must map BOTH the raw Devin event name (the eventKey) AND the auspex
// lifecycle arg the installer writes into the command (the lifecycle field) to the
// same auspex Lifecycle. This pins that the two entry paths never drift — in
// particular that the tool moments stay on the Devin-specific (non-generic) lifecycles.
func TestDevinInstallerResolverLifecycleParity(t *testing.T) {
	for _, ev := range devinHookEvents {
		fromArg, err := ResolveLifecycle(AgentDevin, ev.lifecycle)
		if err != nil {
			t.Errorf("ResolveLifecycle(devin, lifecycle arg %q): %v", ev.lifecycle, err)
			continue
		}
		fromRaw, err := ResolveLifecycle(AgentDevin, ev.eventKey)
		if err != nil {
			t.Errorf("ResolveLifecycle(devin, raw event %q): %v", ev.eventKey, err)
			continue
		}
		if fromArg != fromRaw {
			t.Errorf("event %q: installer lifecycle arg %q resolves to %q but raw event resolves to %q (installer/runtime drift)",
				ev.eventKey, ev.lifecycle, fromArg, fromRaw)
		}
	}
	wired := map[string]string{}
	for _, ev := range devinHookEvents {
		wired[ev.eventKey] = ev.lifecycle
	}
	if wired["PreToolUse"] != string(LifecycleDevinPreTool) {
		t.Errorf("PreToolUse wired to %q, want %q (must not use generic pre-tool)", wired["PreToolUse"], LifecycleDevinPreTool)
	}
	if wired["PostToolUse"] != string(LifecycleDevinPostTool) {
		t.Errorf("PostToolUse wired to %q, want %q (must not use generic post-tool)", wired["PostToolUse"], LifecycleDevinPostTool)
	}
	if wired["PermissionRequest"] != string(LifecycleDevinPermission) {
		t.Errorf("PermissionRequest wired to %q, want %q (observe-only Devin permission lifecycle)", wired["PermissionRequest"], LifecycleDevinPermission)
	}
	if wired["Stop"] != string(LifecycleStop) {
		t.Errorf("Stop wired to %q, want %q (Devin keeps a distinct stop moment)", wired["Stop"], LifecycleStop)
	}
}

// readDevinTop loads a Devin file into a generic top-level map for assertions.
func readDevinTop(t *testing.T, path string) map[string]json.RawMessage {
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

// devinProjectPath returns a standalone project hooks file path under a temp dir.
func devinProjectPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), ".devin", devinProjectFile)
}

// TestDevinStandaloneInstallWritesSevenEvents verifies a fresh STANDALONE project
// install drops .devin/hooks.v1.json whose TOP-LEVEL JSON is the hooks map itself
// (no wrapping "hooks" key), with exactly the seven wired events, each a command hook
// carrying the marker and --agent devin, 0600 perms, 0700 dir — installed+changed.
func TestDevinStandaloneInstallWritesSevenEvents(t *testing.T) {
	path := devinProjectPath(t)
	rep, err := Install(AgentDevin, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}

	// Standalone: the top-level object IS the hooks map (event keys at the top level).
	var hooks devinHooks
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("parse standalone hooks map: %v", err)
	}
	wantEvents := []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop", "SessionEnd"}
	if len(hooks) != len(wantEvents) {
		t.Fatalf("hooks has %d events, want %d: %v", len(hooks), len(wantEvents), hooks)
	}
	for _, ev := range wantEvents {
		groups, ok := hooks[ev]
		if !ok {
			t.Errorf("missing event %q", ev)
			continue
		}
		if len(groups) != 1 || len(groups[0].Hooks) != 1 {
			t.Errorf("event %q: want exactly one group with one hook, got %+v", ev, groups)
			continue
		}
		h := groups[0].Hooks[0]
		command := hookCommandText(h.Command)
		if h.Type != "command" {
			t.Errorf("event %q hook type = %q, want command", ev, h.Type)
		}
		if !strings.Contains(command, auspexHookMarker) {
			t.Errorf("event %q command missing marker: %q", ev, h.Command)
		}
		if !strings.Contains(command, "--agent devin") {
			t.Errorf("event %q command must target --agent devin: %q", ev, h.Command)
		}
		if strings.Contains(command, "--enforce") {
			t.Errorf("event %q command must not carry --enforce: %q", ev, h.Command)
		}
	}
	// The tool moments must carry the Devin-specific lifecycle args, not generic ones.
	if cmd := hooks["PreToolUse"][0].Hooks[0].Command; !strings.Contains(hookCommandText(cmd), string(LifecycleDevinPreTool)) {
		t.Errorf("PreToolUse command must carry devin-pre-tool: %q", cmd)
	}
	if cmd := hooks["PostToolUse"][0].Hooks[0].Command; !strings.Contains(hookCommandText(cmd), string(LifecycleDevinPostTool)) {
		t.Errorf("PostToolUse command must carry devin-post-tool: %q", cmd)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks file perms = %o, want 600", perm)
	}
	dinfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dinfo.Mode().Perm(); !modeMatches(perm, 0o700) {
		t.Errorf("hooks dir perms = %o, want 700", perm)
	}
}

// TestDevinEmbeddedInstallNestsUnderHooksKey verifies a USER-scope install into
// config.json nests the hooks map under a "hooks" key (NOT the top level) and
// preserves a foreign top-level key byte-for-byte.
func TestDevinEmbeddedInstallNestsUnderHooksKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devin", "config.json")
	const seeded = `{"theme":"dark","editor":{"tabs":2}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	top := readDevinTop(t, path)
	if _, ok := top["theme"]; !ok {
		t.Errorf("foreign top-level key 'theme' dropped on install; keys = %v", topKeys(top))
	}
	if _, ok := top["editor"]; !ok {
		t.Errorf("foreign top-level key 'editor' dropped on install; keys = %v", topKeys(top))
	}
	raw, ok := top["hooks"]
	if !ok {
		t.Fatalf("embedded config missing 'hooks' key; keys = %v", topKeys(top))
	}
	var hooks devinHooks
	if err := json.Unmarshal(raw, &hooks); err != nil {
		t.Fatalf("parse embedded hooks: %v", err)
	}
	if _, ok := hooks["PermissionRequest"]; !ok {
		t.Errorf("embedded hooks missing PermissionRequest; got %v", hooks)
	}
}

// TestDevinInstallIsIdempotent: a second install yields byte-identical content
// (auspex's groups rebuilt fresh, never duplicated) and reports installed. Run for
// BOTH scopes.
func TestDevinInstallIsIdempotent(t *testing.T) {
	scopes := map[string]string{
		"standalone": devinProjectPath(t),
		"embedded":   filepath.Join(t.TempDir(), "devin", "config.json"),
	}
	for name, path := range scopes {
		t.Run(name, func(t *testing.T) {
			if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			first, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read 1: %v", err)
			}
			if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
			second, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read 2: %v", err)
			}
			if string(first) != string(second) {
				t.Errorf("re-install produced different content:\n%s\n---\n%s", first, second)
			}
			if rep := Status(AgentDevin, path); !rep.Installed {
				t.Error("status after re-install should be installed")
			}
		})
	}
}

// TestDevinInstallWiresDurableOutputFile: when an output file is supplied, the wired
// command threads --output=file and the path.
func TestDevinInstallWiresDurableOutputFile(t *testing.T) {
	path := devinProjectPath(t)
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentDevin, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	var hooks devinHooks
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("parse hooks: %v", err)
	}
	cmd := hooks["PreToolUse"][0].Hooks[0].Command
	if command := hookCommandText(cmd); !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
		t.Errorf("command missing durable output wiring: %q", cmd)
	}
}

// TestDevinStandalonePreservesForeignContent: a foreign event group inside a
// standalone file is preserved verbatim across install and uninstall — auspex only
// ever touches its own marked groups.
func TestDevinStandalonePreservesForeignContent(t *testing.T) {
	path := devinProjectPath(t)
	const seeded = `{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	var hooks devinHooks
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("parse hooks: %v", err)
	}
	var foundForeign, foundAuspex bool
	for _, g := range hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, "echo foreign") {
				foundForeign = true
			}
			if isAuspexHookCommand(h.Command) {
				foundAuspex = true
			}
		}
	}
	if !foundForeign {
		t.Errorf("foreign PreToolUse group dropped on install: %+v", hooks["PreToolUse"])
	}
	if !foundAuspex {
		t.Errorf("auspex PreToolUse group missing after install: %+v", hooks["PreToolUse"])
	}

	// Uninstall must strip only auspex's groups and leave the foreign content — the
	// standalone file is NOT removed because a foreign group remains.
	rep, err := Uninstall(AgentDevin, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("standalone file with surviving foreign group must NOT be removed: %v", statErr)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if !strings.Contains(string(data), "echo foreign") {
		t.Errorf("foreign hook group mutated on uninstall: %s", data)
	}
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatalf("parse hooks after uninstall: %v", err)
	}
	if hasAuspexGroup(hooks["PreToolUse"]) {
		t.Errorf("auspex group survived uninstall: %+v", hooks["PreToolUse"])
	}
}

// TestDevinEmbeddedUninstallPreservesForeignKeys: uninstalling an embedded config that
// auspex shared with foreign keys drops only the hooks key and leaves the rest — the
// config.json file is NEVER removed.
func TestDevinEmbeddedUninstallPreservesForeignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devin", "config.json")
	const seeded = `{"theme":"dark"}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentDevin, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("embedded config.json must NOT be removed on uninstall: %v", statErr)
	}
	top := readDevinTop(t, path)
	if _, ok := top["theme"]; !ok {
		t.Errorf("foreign key 'theme' removed on uninstall; keys = %v", topKeys(top))
	}
	if _, ok := top["hooks"]; ok {
		t.Errorf("hooks key should be dropped after uninstall; keys = %v", topKeys(top))
	}
}

// TestDevinStandaloneUninstallRemovesEmptiedFile: when auspex was the only content of
// a STANDALONE project file, uninstall removes the file rather than leaving a bare {}.
func TestDevinStandaloneUninstallRemovesEmptiedFile(t *testing.T) {
	path := devinProjectPath(t)
	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentDevin, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("emptied standalone hooks file should be removed, stat err = %v", statErr)
	}
}

// TestDevinBackupPreservesPristineOriginal: a pre-existing file is backed up once with
// its original content before being overwritten.
func TestDevinBackupPreservesPristineOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devin", "config.json")
	const pristine = `{"theme":"dark"}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(pristine), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(data) != pristine {
		t.Errorf("backup is not the pristine original: %s", data)
	}
}

// TestDevinDetectionIsRenameProof: detection keys on the auspex command marker, not
// the binary path, so a binary with no "auspex" in its name still installs, reports
// installed, and uninstalls.
func TestDevinDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := devinProjectPath(t)
	if _, err := Install(AgentDevin, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentDevin, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	rep, err := Uninstall(AgentDevin, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
}

// TestDevinUninstallNoFileIsNoOp: uninstalling when no file exists is a clean no-op.
func TestDevinUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", devinProjectFile)
	rep, err := Uninstall(AgentDevin, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

// TestDevinStatusReflectsInstallState: status is not-installed before install,
// installed after.
func TestDevinStatusReflectsInstallState(t *testing.T) {
	path := devinProjectPath(t)
	if rep := Status(AgentDevin, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentDevin, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestDevinEnforceInstallThreadsOnlyPreTool(t *testing.T) {
	path := devinProjectPath(t)
	if _, err := Install(AgentDevin, path, auspexBinary, "", true); err != nil {
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

func TestDevinUserConfigPathPlatforms(t *testing.T) {
	tests := []struct {
		name, home, goos, xdg, appData, want string
	}{
		{"unix default", "/home/u", "linux", "", "", filepath.Join("/home/u", ".config", "devin", "config.json")},
		{"unix xdg", "/home/u", "linux", "/cfg", "", filepath.Join("/cfg", "devin", "config.json")},
		{"windows appdata", `C:\Users\u`, "windows", "", `C:\Users\u\AppData\Roaming`, filepath.Join(`C:\Users\u\AppData\Roaming`, "devin", "config.json")},
		{"windows fallback", `C:\Users\u`, "windows", "", "", filepath.Join(`C:\Users\u`, "AppData", "Roaming", "devin", "config.json")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := devinUserConfigPath(tc.home, tc.goos, tc.xdg, tc.appData); got != tc.want {
				t.Fatalf("path = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDevinStandaloneUninstallUnrecognizedFileIsNoOp: a standalone Devin file with NO
// auspex command is not auspex-recognized, so uninstall is a no-op that leaves the
// foreign content byte-for-byte untouched.
func TestDevinStandaloneUninstallUnrecognizedFileIsNoOp(t *testing.T) {
	path := devinProjectPath(t)
	const foreign = `{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rep, err := Uninstall(AgentDevin, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall of an unrecognized foreign file must not report a change")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if string(got) != foreign {
		t.Errorf("foreign file mutated by uninstall:\n got = %s\nwant = %s", got, foreign)
	}
}

// TestDevinProjectScopeHasNoTrustNote: unlike Grok, Devin appends NO trust note on a
// project-scope install — its message is the plain observe-only confirmation.
func TestDevinProjectScopeHasNoTrustNote(t *testing.T) {
	path := devinProjectPath(t)
	rep, err := Install(AgentDevin, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if strings.Contains(strings.ToLower(rep.Message), "trust") {
		t.Errorf("devin install message must not mention trust: %q", rep.Message)
	}
}

// TestDevinPaths pins the two scope path shapes.
func TestDevinPaths(t *testing.T) {
	proj := DevinProjectHooksPath("/work/repo")
	if filepath.Base(proj) != devinProjectFile {
		t.Errorf("project path base = %q, want %q", filepath.Base(proj), devinProjectFile)
	}
	if filepath.Base(filepath.Dir(proj)) != ".devin" {
		t.Errorf("project path parent = %q, want .devin", filepath.Base(filepath.Dir(proj)))
	}
	if !isDevinStandalone(proj) {
		t.Errorf("%q should be detected as standalone", proj)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	user := DevinUserConfigPath("/home/u")
	if filepath.Base(user) != "config.json" {
		t.Errorf("user path base = %q, want config.json", filepath.Base(user))
	}
	if filepath.Base(filepath.Dir(user)) != "devin" {
		t.Errorf("user path parent = %q, want devin", filepath.Base(filepath.Dir(user)))
	}
	if isDevinStandalone(user) {
		t.Errorf("%q should NOT be detected as standalone (embedded config)", user)
	}

	// XDG_CONFIG_HOME overrides the Unix ~/.config root. Use the pure path
	// helper so this assertion remains meaningful on a Windows test host.
	if got := devinUserConfigPath("/home/u", "linux", "/xdg", ""); got != filepath.Join("/xdg", "devin", "config.json") {
		t.Errorf("XDG override path = %q, want /xdg/devin/config.json", got)
	}
}

// Devin's JSONC reader preserves comment-like sequences inside string values.
func TestDevinEmbeddedInstallToleratesCommentedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devin", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A commented config: a // line comment, a /* */ block comment, a foreign top-level
	// key whose value embeds // and /* sequences inside a string, and a foreign hook.
	const seeded = `{
  // user theme preference
  "theme": "dark",
  /* the endpoint must survive byte-for-byte, including its // and /* sequences */
  "endpoint": "https://example.com/path/*glob*/",
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "echo foreign-hook"}]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rep, err := Install(AgentDevin, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install on commented config errored (comment stripper missing?): %v", err)
	}
	if !rep.Installed {
		t.Fatalf("install report not installed: %+v", rep)
	}
	top := readDevinTop(t, path)
	// (c) the foreign top-level key with //- and /*-bearing string value is preserved
	// byte-for-byte: the in-string sequences were NOT treated as comments.
	endpoint, ok := top["endpoint"]
	if !ok {
		t.Fatalf("foreign key 'endpoint' dropped; keys = %v", topKeys(top))
	}
	var endpointVal string
	if err := json.Unmarshal(endpoint, &endpointVal); err != nil {
		t.Fatalf("parse endpoint value: %v", err)
	}
	if endpointVal != "https://example.com/path/*glob*/" {
		t.Errorf("endpoint value = %q, want %q (in-string //, /* mangled by stripper)", endpointVal, "https://example.com/path/*glob*/")
	}
	if _, ok := top["theme"]; !ok {
		t.Errorf("foreign key 'theme' dropped; keys = %v", topKeys(top))
	}
	// (b) the seven auspex events are wired under hooks (foreign SessionStart hook kept).
	raw, ok := top["hooks"]
	if !ok {
		t.Fatalf("hooks key missing after install; keys = %v", topKeys(top))
	}
	var hooks devinHooks
	if err := json.Unmarshal(raw, &hooks); err != nil {
		t.Fatalf("parse hooks: %v", err)
	}
	for _, ev := range devinHookEvents {
		groups, ok := hooks[ev.eventKey]
		if !ok || !hasAuspexGroup(groups) {
			t.Errorf("event %q not wired with a auspex group after install", ev.eventKey)
		}
	}
	if !hasForeignSessionStartHook(hooks) {
		t.Errorf("foreign SessionStart hook lost on install; hooks = %v", hooks)
	}
	// (d) status reports installed against the (now canonical) config.
	if rep := Status(AgentDevin, path); !rep.Installed {
		t.Errorf("status after install should be installed: %+v", rep)
	}
}

func TestDevinEmbeddedInstallRejectsUnterminatedBlockComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devin", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seed := []byte(`{"theme":"dark"} /* unfinished`)
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := Install(AgentDevin, path, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), "unterminated block comment") {
		t.Fatalf("Install error = %v, want unterminated block comment", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(seed) {
		t.Fatalf("malformed config was rewritten: %q", got)
	}
	if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
		t.Fatalf("backup should not be created before successful parse; stat error = %v", err)
	}
}

// hasForeignSessionStartHook reports whether the SessionStart event still carries the
// non-auspex "echo foreign-hook" group seeded by the test.
func hasForeignSessionStartHook(hooks devinHooks) bool {
	for _, g := range hooks["SessionStart"] {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, "echo foreign-hook") {
				return true
			}
		}
	}
	return false
}

// Devin's pre-decision payload must ignore unrelated verdict-like keys.
func TestMapDevinPermissionRequestIgnoresVerdictKeys(t *testing.T) {
	payload := map[string]any{
		"tool_name":           "Bash",
		"tool_input":          map[string]any{"command": "rm -rf /"},
		"decision":            "denied",
		"permission_decision": "deny",
		"permissionDecision":  "deny",
		"behavior":            "deny",
	}
	ev := Map(LifecycleDevinPermission, AgentDevin, model.AgentDevinCLI, "perm", payload)
	assertHookProvenance(t, ev)
	if ev.EventType != model.EventPermissionRequested {
		t.Errorf("event type = %q, want %q (verdict keys must be IGNORED, not restamped)", ev.EventType, model.EventPermissionRequested)
	}
	if ev.Decision != model.DecisionAsked {
		t.Errorf("decision = %q, want %q (verdict keys must not restamp a deny)", ev.Decision, model.DecisionAsked)
	}
	if ev.ApprovalDecision != model.DecisionAsked {
		t.Errorf("approval decision = %q, want %q (verdict keys must not restamp a deny)", ev.ApprovalDecision, model.DecisionAsked)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("mapped devin permission event failed Validate: %v", err)
	}
}
