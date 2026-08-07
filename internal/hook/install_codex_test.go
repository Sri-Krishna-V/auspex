package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readCodexHooks loads the hooks block from a Codex hooks.json for assertions.
// Codex reuses the Claude nested-schema reader since the schema (hooks map of
// event→[{matcher,hooks:[{type,command,timeout}]}]) is identical.
func readCodexHooks(t *testing.T, path string) map[string][]hookGroup {
	t.Helper()
	sf, err := readSettings(path)
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	return sf.hooks
}

// countCodexAuspexHooks counts auspex-installed hook refs across all events.
func countCodexAuspexHooks(hooks map[string][]hookGroup) int {
	n := 0
	for _, groups := range hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isAuspexHookRef(h) {
					n++
				}
			}
		}
	}
	return n
}

func TestCodexInstallCreatesAllEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codex", "hooks.json")
	rep, err := Install(AgentCodex, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}
	hooks := readCodexHooks(t, path)
	if got, want := countCodexAuspexHooks(hooks), len(codexHookEvents); got != want {
		t.Fatalf("installed %d auspex hooks, want one per event (%d)", got, want)
	}
	// The schema is the Claude nested shape: a hooks map keyed by Codex event names,
	// each carrying a {matcher, hooks:[{type,command,timeout}]} group.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json is not valid: %v", err)
	}
	for _, ev := range codexHookEvents {
		groups, ok := parsed.Hooks[ev.settingsKey]
		if !ok || len(groups) == 0 {
			t.Errorf("event %q missing from installed hooks", ev.settingsKey)
			continue
		}
		var cmd string
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isAuspexHookRef(h) {
					cmd = h.Command
					if h.Type != "command" {
						t.Errorf("event %q hook type = %q, want command", ev.settingsKey, h.Type)
					}
					if h.Timeout != ev.timeout {
						t.Errorf("event %q timeout = %d, want %d", ev.settingsKey, h.Timeout, ev.timeout)
					}
				}
			}
		}
		if cmd == "" {
			t.Errorf("event %q has no auspex command", ev.settingsKey)
			continue
		}
		cmd = hookCommandText(cmd)
		if !strings.Contains(cmd, "hook "+ev.lifecycle) || !strings.Contains(cmd, "--agent codex") {
			t.Errorf("event %q command malformed: %q", ev.settingsKey, cmd)
		}
		// OBSERVE-ONLY: a default install never threads --enforce into a Codex command.
		if strings.Contains(cmd, "--enforce") {
			t.Errorf("event %q command must not carry --enforce on a default install: %q", ev.settingsKey, cmd)
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

func TestCodexInstallWiresMappedEvents(t *testing.T) {
	want := []string{
		"PreToolUse", "PermissionRequest", "PostToolUse", "SessionStart",
		"SubagentStart", "SubagentStop", "UserPromptSubmit", "Stop",
	}
	if len(codexHookEvents) != len(want) {
		t.Fatalf("codexHookEvents has %d entries, want %d", len(codexHookEvents), len(want))
	}
	have := map[string]bool{}
	for _, ev := range codexHookEvents {
		have[ev.settingsKey] = true
		if ev.settingsKey == "PreToolUse" && ev.matcher != ".*" {
			t.Errorf("PreToolUse matcher = %q, want match-all", ev.matcher)
		}
	}
	for _, k := range want {
		if !have[k] {
			t.Errorf("mapped Codex event %q is not wired", k)
		}
	}
}

func TestCodexInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hooks := readCodexHooks(t, path)
	if got, want := countCodexAuspexHooks(hooks), len(codexHookEvents); got != want {
		t.Fatalf("after two installs got %d auspex hooks, want %d (no duplicates)", got, want)
	}
}

func TestCodexInstallPreservesUnrelatedKeysAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	// A pre-existing hooks.json with an unrelated top-level key and a user-defined
	// PreToolUse hook auspex must not disturb.
	seed := map[string]any{
		"customConfig": map[string]any{"foo": "bar"},
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/opt/user-audit shell"},
					},
				},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
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

	sf, err := readSettings(path)
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	foundUser := false
	for _, g := range sf.hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if h.Command == "/opt/user-audit shell" {
				foundUser = true
			}
		}
	}
	if !foundUser {
		t.Error("user's PreToolUse hook was dropped")
	}
	if countCodexAuspexHooks(sf.hooks) != len(codexHookEvents) {
		t.Errorf("auspex hooks = %d, want %d", countCodexAuspexHooks(sf.hooks), len(codexHookEvents))
	}
}

func TestCodexUninstallRemovesOnlyAuspexHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/opt/user-audit shell"},
					},
				},
			},
		},
	}
	writeJSON(t, path, seed)
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentCodex, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	if countCodexAuspexHooks(sf.hooks) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %+v", sf.hooks)
	}
	foundUser := false
	for _, g := range sf.hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if h.Command == "/opt/user-audit shell" {
				foundUser = true
			}
		}
	}
	if !foundUser {
		t.Error("uninstall removed the user's unrelated hook")
	}
}

// Uninstalling from a file that held ONLY auspex entries must still leave a valid
// Codex hooks.json — the hooks map must remain present (even if empty), not be
// dropped (same lesson as the Cursor/Windsurf installers).
func TestCodexUninstallLeavesValidSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(AgentCodex, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("post-uninstall hooks.json is not valid: %v (%s)", err, data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall file dropped the hooks map: %s", data)
	}
	if countCodexAuspexHooks(readCodexHooks(t, path)) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %s", data)
	}
}

func TestCodexUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	rep, err := Uninstall(AgentCodex, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

func TestCodexStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if rep := Status(AgentCodex, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentCodex, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestCodexMalformedSettingsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err == nil {
		t.Error("Install on malformed hooks.json should error rather than corrupt the file")
	}
}

// Detection keys on the auspex marker, not the binary path, so a binary with no
// "auspex" in its name still installs, reports installed, uninstalls cleanly, and
// reinstalls without duplicating entries.
func TestCodexInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCodex, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentCodex, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if got := countCodexAuspexHooks(readCodexHooks(t, path)); got != len(codexHookEvents) {
		t.Fatalf("after install got %d hooks, want %d", got, len(codexHookEvents))
	}
	if _, err := Install(AgentCodex, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if got := countCodexAuspexHooks(readCodexHooks(t, path)); got != len(codexHookEvents) {
		t.Fatalf("after reinstall got %d hooks, want %d (no duplicates)", got, len(codexHookEvents))
	}
	rep, err := Uninstall(AgentCodex, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if got := countCodexAuspexHooks(readCodexHooks(t, path)); got != 0 {
		t.Errorf("hooks remain after uninstall: %d", got)
	}
}

// The backup must preserve the pristine pre-auspex original across repeated
// install / install→uninstall→install cycles.
func TestCodexBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/keep me"}]}]}}`
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
			if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentCodex, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// A pre-existing 0644 hooks.json must be tightened to 0600 after an in-place
// rewrite, since it can carry tokens.
func TestCodexInstallEnforces0600OnPreExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
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
func TestCodexInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentCodex, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	n := 0
	for _, groups := range sf.hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if !isAuspexHookRef(h) {
					continue
				}
				n++
				command := hookCommandText(h.Command)
				if !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
					t.Errorf("command missing durable output wiring: %q", h.Command)
				}
			}
		}
	}
	if n != len(codexHookEvents) {
		t.Fatalf("wired %d auspex commands, want %d", n, len(codexHookEvents))
	}
}

// Codex is enforce-capable at PreToolUse: an --enforce install for Codex
// SUCCEEDS and threads the --enforce flag into every wired command, mirroring the
// Claude installer. The runtime gate confines an actual deny to PreToolUse; the
// install simply carries the opt-in flag. The file must
// land 0600 and report installed.
func TestCodexEnforceInstallSucceedsAndThreadsFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codex", "hooks.json")
	rep, err := Install(AgentCodex, path, auspexBinary, "", true)
	if err != nil {
		t.Fatalf("enforce install for codex should succeed, got %v", err)
	}
	if !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want installed+changed", rep)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var parsed struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json is not valid: %v", err)
	}
	// Only PreToolUse carries --enforce; passive events do not pay enforce-mode
	// processing latency.
	for _, ev := range codexHookEvents {
		groups := parsed.Hooks[ev.settingsKey]
		var cmd string
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isAuspexHookRef(h) {
					cmd = h.Command
				}
			}
		}
		if cmd == "" {
			t.Errorf("event %q has no auspex command", ev.settingsKey)
			continue
		}
		cmd = hookCommandText(cmd)
		if got, want := strings.Contains(cmd, "--enforce"), ev.settingsKey == "PreToolUse"; got != want {
			t.Errorf("event %q enforce flag = %v, want %v: %q", ev.settingsKey, got, want, cmd)
		}
		if !strings.Contains(cmd, "--agent codex") {
			t.Errorf("event %q command malformed: %q", ev.settingsKey, cmd)
		}
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	} else if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks.json perms = %o, want 600", perm)
	}
}

// A DEFAULT (observe) Codex install must be unchanged by the enforce work: no
// command carries --enforce, exactly as before. This pins that --enforce stays
// strictly opt-in for Codex.
func TestCodexObserveInstallUnchangedNoEnforceFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codex", "hooks.json")
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("observe install for codex: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if strings.Contains(hookCommandText(string(data)), "--enforce") {
		t.Fatalf("observe install must not carry --enforce: %s", data)
	}
}

// CodexSettingsPath defaults to ~/.codex/hooks.json but honors CODEX_HOME when
// set, so an install lands in the same root Codex itself reads from. macOS-safe:
// assert on the trailing path segments (filepath.Base / suffix), not a full-path
// equality that a /var→/private/var symlink would break.
func TestCodexSettingsPathHonorsCodexHome(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	def := CodexSettingsPath("/home/u")
	if filepath.Base(def) != "hooks.json" {
		t.Errorf("default path base = %q, want hooks.json", filepath.Base(def))
	}
	if filepath.Base(filepath.Dir(def)) != ".codex" {
		t.Errorf("default path parent = %q, want .codex", filepath.Base(filepath.Dir(def)))
	}

	custom := t.TempDir()
	t.Setenv("CODEX_HOME", custom)
	got := CodexSettingsPath("/home/u")
	if filepath.Base(got) != "hooks.json" {
		t.Errorf("CODEX_HOME path base = %q, want hooks.json", filepath.Base(got))
	}
	// The directory must be the CODEX_HOME root itself (not ~/.codex under it).
	if filepath.Base(filepath.Dir(got)) != filepath.Base(custom) {
		t.Errorf("CODEX_HOME path parent = %q, want %q", filepath.Dir(got), custom)
	}
	if strings.Contains(got, ".codex") {
		t.Errorf("CODEX_HOME path must not append .codex: %q", got)
	}
}

// An install through the CODEX_HOME-resolved path round-trips: the file lands
// under the override root and reports installed.
func TestCodexInstallUnderCodexHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	path := CodexSettingsPath("/unused/home")
	if _, err := Install(AgentCodex, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentCodex, path); !rep.Installed {
		t.Fatalf("status after install under CODEX_HOME = not-installed")
	}
	if filepath.Dir(path) != root {
		t.Errorf("install path dir = %q, want CODEX_HOME root %q", filepath.Dir(path), root)
	}
}
