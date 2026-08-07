package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// readWindsurfHooks loads the hooks block from a Windsurf hooks.json for
// assertions.
func readWindsurfHooks(t *testing.T, path string) map[string][]json.RawMessage {
	t.Helper()
	ws, err := readWindsurfSettings(path)
	if err != nil {
		t.Fatalf("readWindsurfSettings: %v", err)
	}
	return ws.hooks
}

// rawKeys returns the sorted key set of a raw JSON object, for diagnostics when
// an expected field is missing from a wired entry.
func rawKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// countWindsurfAuspexHooks counts auspex-installed entries across all events.
func countWindsurfAuspexHooks(hooks map[string][]json.RawMessage) int {
	n := 0
	for _, entries := range hooks {
		for _, raw := range entries {
			if windsurfEntryIsAuspex(raw) {
				n++
			}
		}
	}
	return n
}

func TestWindsurfInstallCreatesAllEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codeium", "windsurf", "hooks.json")
	rep, err := Install(AgentWindsurf, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}
	hooks := readWindsurfHooks(t, path)
	if got, want := countWindsurfAuspexHooks(hooks), len(windsurfHookEvents); got != want {
		t.Fatalf("installed %d auspex hooks, want one per event (%d)", got, want)
	}
	// The schema is a hooks map keyed by Windsurf event names; each entry carries
	// the verified Windsurf shape {command, show_output, working_directory}. There
	// is no top-level version (unlike Cursor).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The file must carry no top-level "version" key — Windsurf's schema, unlike
	// Cursor's, has none, and emitting a stray one could trip a strict validator.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("installed hooks.json is not valid: %v", err)
	}
	if _, ok := top["version"]; ok {
		t.Errorf("installed Windsurf hooks.json must not carry a top-level version key: %s", data)
	}
	// Decode entries as raw objects so the presence of each key can be asserted on
	// the wire (a zero-valued field would still decode into the typed struct).
	var parsedRaw struct {
		Hooks map[string][]map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsedRaw); err != nil {
		t.Fatalf("installed hooks.json is not valid: %v", err)
	}
	for _, event := range windsurfHookEvents {
		entries, ok := parsedRaw.Hooks[event]
		if !ok || len(entries) == 0 {
			t.Errorf("event %q missing from installed hooks", event)
			continue
		}
		raw := entries[0]
		for _, key := range []string{"command", "show_output", "working_directory"} {
			if _, ok := raw[key]; !ok {
				t.Errorf("event %q entry missing %q key; got keys %v", event, key, rawKeys(raw))
			}
		}
		entryBytes, _ := json.Marshal(raw)
		var e windsurfHookEntry
		if err := json.Unmarshal(entryBytes, &e); err != nil {
			t.Fatalf("event %q entry not a windsurfHookEntry: %v", event, err)
		}
		command := hookCommandText(e.Command)
		if !strings.Contains(command, "hook "+event) || !strings.Contains(command, "--agent windsurf") {
			t.Errorf("event %q command malformed: %q", event, e.Command)
		}
		if e.ShowOutput {
			t.Errorf("event %q show_output = true, want false", event)
		}
		if e.WorkingDirectory != windsurfWorkingDir {
			t.Errorf("event %q working_directory = %q, want %q", event, e.WorkingDirectory, windsurfWorkingDir)
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

func TestWindsurfInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hooks := readWindsurfHooks(t, path)
	if got, want := countWindsurfAuspexHooks(hooks), len(windsurfHookEvents); got != want {
		t.Fatalf("after two installs got %d auspex hooks, want %d (no duplicates)", got, want)
	}
}

func TestWindsurfInstallPreservesUnrelatedKeysAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	// A pre-existing hooks.json with an unrelated top-level key and a user-defined
	// pre_run_command hook auspex must not disturb; the user entry carries extra
	// keys that must round-trip untouched.
	seed := map[string]any{
		"customConfig": map[string]any{"foo": "bar"},
		"hooks": map[string]any{
			"pre_run_command": []any{
				map[string]any{"command": "/opt/user-audit shell", "show_output": true, "note": "keep me"},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
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

	ws, err := readWindsurfSettings(path)
	if err != nil {
		t.Fatalf("readWindsurfSettings: %v", err)
	}
	foundUser := false
	for _, raw := range ws.hooks["pre_run_command"] {
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
		t.Error("user's pre_run_command hook was dropped")
	}
	if countWindsurfAuspexHooks(ws.hooks) != len(windsurfHookEvents) {
		t.Errorf("auspex hooks = %d, want %d", countWindsurfAuspexHooks(ws.hooks), len(windsurfHookEvents))
	}
}

func TestWindsurfUninstallRemovesOnlyAuspexHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"pre_run_command": []any{
				map[string]any{"command": "/opt/user-audit shell", "show_output": false},
			},
		},
	}
	writeJSON(t, path, seed)
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentWindsurf, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	ws, err := readWindsurfSettings(path)
	if err != nil {
		t.Fatalf("readWindsurfSettings: %v", err)
	}
	if countWindsurfAuspexHooks(ws.hooks) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %+v", ws.hooks)
	}
	foundUser := false
	for _, raw := range ws.hooks["pre_run_command"] {
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

// Uninstall leaves Windsurf's required hooks map present, even when empty.
func TestWindsurfUninstallLeavesValidSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(AgentWindsurf, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string][]windsurfHookEntry `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("post-uninstall hooks.json is not valid: %v (%s)", err, data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall file dropped the hooks map: %s", data)
	}
	if countWindsurfAuspexHooks(readWindsurfHooks(t, path)) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %s", data)
	}
}

func TestWindsurfUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	rep, err := Uninstall(AgentWindsurf, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

func TestWindsurfStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if rep := Status(AgentWindsurf, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentWindsurf, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestWindsurfMalformedSettingsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err == nil {
		t.Error("Install on malformed hooks.json should error rather than corrupt the file")
	}
}

// Detection keys on the auspex marker, not the binary path, so a binary with no
// "auspex" in its name still installs, reports installed, uninstalls cleanly, and
// reinstalls without duplicating entries.
func TestWindsurfInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentWindsurf, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentWindsurf, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if got := countWindsurfAuspexHooks(readWindsurfHooks(t, path)); got != len(windsurfHookEvents) {
		t.Fatalf("after install got %d hooks, want %d", got, len(windsurfHookEvents))
	}
	if _, err := Install(AgentWindsurf, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if got := countWindsurfAuspexHooks(readWindsurfHooks(t, path)); got != len(windsurfHookEvents) {
		t.Fatalf("after reinstall got %d hooks, want %d (no duplicates)", got, len(windsurfHookEvents))
	}
	rep, err := Uninstall(AgentWindsurf, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if got := countWindsurfAuspexHooks(readWindsurfHooks(t, path)); got != 0 {
		t.Errorf("hooks remain after uninstall: %d", got)
	}
}

// The backup must preserve the pristine pre-auspex original across repeated
// install / install→uninstall→install cycles.
func TestWindsurfBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = `{"hooks":{"pre_run_command":[{"command":"/opt/keep me","show_output":false}]}}`
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
			if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentWindsurf, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// A pre-existing 0644 hooks.json must be tightened to 0600 after an in-place
// rewrite, since it can carry tokens.
func TestWindsurfInstallEnforces0600OnPreExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", false); err != nil {
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
func TestWindsurfInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentWindsurf, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	ws, err := readWindsurfSettings(path)
	if err != nil {
		t.Fatalf("readWindsurfSettings: %v", err)
	}
	n := 0
	for _, entries := range ws.hooks {
		for _, raw := range entries {
			if !windsurfEntryIsAuspex(raw) {
				continue
			}
			n++
			var e windsurfHookEntry
			_ = json.Unmarshal(raw, &e)
			command := hookCommandText(e.Command)
			if !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
				t.Errorf("command missing durable output wiring: %q", e.Command)
			}
		}
	}
	if n != len(windsurfHookEvents) {
		t.Fatalf("wired %d auspex commands, want %d", n, len(windsurfHookEvents))
	}
}

func TestWindsurfEnforceInstallThreadsOnlyBlockingPreHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codeium", "windsurf", "hooks.json")
	if _, err := Install(AgentWindsurf, path, auspexBinary, "", true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(hookCommandText(string(data)), enforceFlag); got != 4 {
		t.Fatalf("enforce flags = %d, want 4 blocking pre-hooks\n%s", got, data)
	}
}

// Windsurf's runtime passthrough is the inert empty object {} — never a block.
// Even though enforce-install is refused, this pins the always-allow runtime
// contract: auspex exits 0 and emits an inert body Windsurf ignores, so the
// observed action always proceeds.
func TestWindsurfPassthroughIsInert(t *testing.T) {
	resp := PassthroughResponse(AgentWindsurf, LifecyclePostTool)
	if len(resp) != 0 {
		t.Errorf("windsurf passthrough = %v, want the inert empty object {}", resp)
	}
}
