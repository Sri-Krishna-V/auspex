package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readCopilotHooks loads the hooks block from a Copilot hooks.json for
// assertions. Copilot reuses the Cursor flat-schema reader since both formats
// use a version plus a flat event-to-entry map.
func readCopilotHooks(t *testing.T, path string) map[string][]json.RawMessage {
	t.Helper()
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	return cs.hooks
}

// countCopilotAuspexHooks counts auspex-installed entries across all events.
func countCopilotAuspexHooks(hooks map[string][]json.RawMessage) int {
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

func TestCopilotInstallCreatesAllEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".copilot", "hooks", "auspex.json")
	rep, err := Install(AgentCopilot, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}
	hooks := readCopilotHooks(t, path)
	if got, want := countCopilotAuspexHooks(hooks), len(copilotHookEvents); got != want {
		t.Fatalf("installed %d auspex hooks, want one per event (%d)", got, want)
	}
	// The schema is a top-level version plus a hooks map keyed by Copilot event
	// names, each carrying a command and its native timeoutSec deadline.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Version json.RawMessage               `json:"version"`
		Hooks   map[string][]copilotHookEntry `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json is not valid: %v", err)
	}
	if len(parsed.Version) == 0 {
		t.Errorf("installed Copilot hooks.json missing top-level version: %s", data)
	}
	for _, event := range copilotHookEvents {
		entries, ok := parsed.Hooks[event.event]
		if !ok || len(entries) == 0 {
			t.Errorf("event %q missing from installed hooks", event.event)
			continue
		}
		cmd := entries[0].Command
		cmd = hookCommandText(cmd)
		if !strings.Contains(cmd, "hook "+event.lifecycle) || !strings.Contains(cmd, "--agent copilot") {
			t.Errorf("event %q command malformed: %q", event.event, cmd)
		}
		if !isAuspexHookCommand(cmd) {
			t.Errorf("event %q command missing auspex marker: %q", event.event, cmd)
		}
		if got := entries[0].TimeoutSec; got != event.timeout {
			t.Errorf("event %q timeoutSec = %d, want %d", event.event, got, event.timeout)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks.json perms = %o, want 600", perm)
	}
}

func TestCopilotSettingsPath(t *testing.T) {
	t.Setenv("COPILOT_HOME", "")
	got := CopilotSettingsPath("/home/u")
	want := filepath.Join("/home/u", ".copilot", "hooks", "auspex.json")
	if got != want {
		t.Fatalf("CopilotSettingsPath = %q, want %q", got, want)
	}
}

func TestCopilotSettingsPathHonorsCopilotHome(t *testing.T) {
	t.Setenv("COPILOT_HOME", "/var/copilot-home")
	got := CopilotSettingsPath("/home/u")
	want := filepath.Join("/var/copilot-home", "hooks", "auspex.json")
	if got != want {
		t.Fatalf("CopilotSettingsPath with COPILOT_HOME = %q, want %q", got, want)
	}
}

func TestCopilotInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hooks := readCopilotHooks(t, path)
	if got, want := countCopilotAuspexHooks(hooks), len(copilotHookEvents); got != want {
		t.Fatalf("after two installs got %d auspex hooks, want %d (no duplicates)", got, want)
	}
}

func TestCopilotInstallPreservesUnrelatedKeysAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	// A pre-existing hooks.json with an unrelated top-level key and a user-defined
	// PreToolUse hook auspex must not disturb; the user entry carries an extra key
	// that must round-trip untouched.
	seed := map[string]any{
		"version":      1,
		"customConfig": map[string]any{"foo": "bar"},
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{"command": "/opt/user-audit shell", "note": "keep me"},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := top["customConfig"]; !ok {
		t.Error("unrelated top-level key customConfig was dropped")
	}

	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	foundUser := false
	for _, raw := range cs.hooks["PreToolUse"] {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if m["command"] == "/opt/user-audit shell" {
			foundUser = true
			if m["note"] != "keep me" {
				t.Errorf("user entry lost its extra key: %v", m)
			}
		}
	}
	if !foundUser {
		t.Error("user's PreToolUse hook was dropped")
	}
	if countCopilotAuspexHooks(cs.hooks) != len(copilotHookEvents) {
		t.Errorf("auspex hooks = %d, want %d", countCopilotAuspexHooks(cs.hooks), len(copilotHookEvents))
	}
}

func TestCopilotUninstallRemovesOnlyAuspexHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	seed := map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{"command": "/opt/user-audit shell"},
			},
		},
	}
	writeJSON(t, path, seed)
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentCopilot, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	if countCopilotAuspexHooks(cs.hooks) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %+v", cs.hooks)
	}
	foundUser := false
	for _, raw := range cs.hooks["PreToolUse"] {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if m["command"] == "/opt/user-audit shell" {
			foundUser = true
		}
	}
	if !foundUser {
		t.Error("uninstall removed the user's unrelated hook")
	}
}

// Uninstall leaves Copilot's required hooks map present, even when empty.
func TestCopilotUninstallLeavesValidSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(AgentCopilot, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string][]cursorHookEntry `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("post-uninstall hooks.json is not valid: %v (%s)", err, data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall file dropped the hooks map: %s", data)
	}
	if countCopilotAuspexHooks(readCopilotHooks(t, path)) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %s", data)
	}
}

func TestCopilotUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	rep, err := Uninstall(AgentCopilot, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

func TestCopilotStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if rep := Status(AgentCopilot, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentCopilot, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestCopilotMalformedSettingsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err == nil {
		t.Error("Install on malformed hooks.json should error rather than corrupt the file")
	}
}

// Detection keys on the auspex marker, not the binary path, so a binary with no
// "auspex" in its name still installs, reports installed, uninstalls cleanly, and
// reinstalls without duplicating entries.
func TestCopilotInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCopilot, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentCopilot, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if got := countCopilotAuspexHooks(readCopilotHooks(t, path)); got != len(copilotHookEvents) {
		t.Fatalf("after install got %d hooks, want %d", got, len(copilotHookEvents))
	}
	if _, err := Install(AgentCopilot, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if got := countCopilotAuspexHooks(readCopilotHooks(t, path)); got != len(copilotHookEvents) {
		t.Fatalf("after reinstall got %d hooks, want %d (no duplicates)", got, len(copilotHookEvents))
	}
	rep, err := Uninstall(AgentCopilot, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if got := countCopilotAuspexHooks(readCopilotHooks(t, path)); got != 0 {
		t.Errorf("hooks remain after uninstall: %d", got)
	}
}

// The backup must preserve the pristine pre-auspex original across repeated
// install / install→uninstall→install cycles.
func TestCopilotBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = `{"version":1,"hooks":{"PreToolUse":[{"command":"/opt/keep me"}]}}`
	check := func(t *testing.T, mutate func(path string)) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if err := os.WriteFile(path, []byte(pristine), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		mutate(path)
		data, err := os.ReadFile(path + backupSuffix)
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if !strings.Contains(string(data), "/opt/keep me") {
			t.Fatalf("backup is not the pristine original: %s", data)
		}
	}
	t.Run("install twice", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentCopilot, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// A pre-existing 0644 hooks.json must be tightened to 0600 after an in-place
// rewrite, since it can carry tokens.
func TestCopilotInstallEnforces0600OnPreExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentCopilot, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks.json perms after install = %o, want 600", perm)
	}
}

// When an output file is supplied, every installed command wires durable findings
// output so a hook-detected finding is not lost to stderr.
func TestCopilotInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentCopilot, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	n := 0
	for _, entries := range cs.hooks {
		for _, raw := range entries {
			if !entryIsAuspex(raw) {
				continue
			}
			n++
			var e cursorHookEntry
			_ = json.Unmarshal(raw, &e)
			command := hookCommandText(e.Command)
			if !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
				t.Errorf("command missing durable output wiring: %q", e.Command)
			}
		}
	}
	if n != len(copilotHookEvents) {
		t.Fatalf("wired %d auspex commands, want %d", n, len(copilotHookEvents))
	}
}
