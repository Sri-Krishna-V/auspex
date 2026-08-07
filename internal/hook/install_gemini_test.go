package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readGeminiHooks loads the hooks block from a Gemini settings.json for assertions.
func readGeminiHooks(t *testing.T, path string) map[string][]geminiHookGroup {
	t.Helper()
	gs, err := readGeminiSettings(path)
	if err != nil {
		t.Fatalf("readGeminiSettings: %v", err)
	}
	return gs.hooks
}

// countGeminiAuspexHooks counts auspex-installed hook refs across all events.
func countGeminiAuspexHooks(hooks map[string][]geminiHookGroup) int {
	n := 0
	for _, groups := range hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isAuspexGeminiHook(h) {
					n++
				}
			}
		}
	}
	return n
}

func TestGeminiInstallCreatesAllEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gemini", "settings.json")
	rep, err := Install(AgentGemini, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}
	hooks := readGeminiHooks(t, path)
	if got, want := countGeminiAuspexHooks(hooks), len(geminiHookEvents); got != want {
		t.Fatalf("installed %d auspex hooks, want one per event (%d)", got, want)
	}
	// The schema is Gemini's nested shape: a hooks map keyed by Gemini event names,
	// each carrying a {matcher, hooks:[{name,type,command,timeout,description}]} group.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string][]geminiHookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed settings.json is not valid: %v", err)
	}
	for _, ev := range geminiHookEvents {
		groups, ok := parsed.Hooks[ev.settingsKey]
		if !ok || len(groups) == 0 {
			t.Errorf("event %q missing from installed hooks", ev.settingsKey)
			continue
		}
		var ref geminiHookRef
		var found bool
		for _, g := range groups {
			// The matcher auspex writes must match the wired event's matcher: a
			// regex (empty = all tools) for the tool moments, an exact-string for
			// the session moments.
			if g.Matcher != ev.matcher {
				t.Errorf("event %q matcher = %q, want %q", ev.settingsKey, g.Matcher, ev.matcher)
			}
			for _, h := range g.Hooks {
				if isAuspexGeminiHook(h) {
					ref = h
					found = true
				}
			}
		}
		if !found {
			t.Errorf("event %q has no auspex hook", ev.settingsKey)
			continue
		}
		if ref.Name != geminiHookName {
			t.Errorf("event %q hook name = %q, want %q", ev.settingsKey, ref.Name, geminiHookName)
		}
		if ref.Type != "command" {
			t.Errorf("event %q hook type = %q, want command", ev.settingsKey, ref.Type)
		}
		command := hookCommandText(ref.Command)
		if !strings.Contains(command, "hook "+ev.lifecycle) || !strings.Contains(command, "--agent gemini") {
			t.Errorf("event %q command malformed: %q", ev.settingsKey, ref.Command)
		}
		// Monitor mode never threads --enforce into a command.
		if strings.Contains(command, "--enforce") {
			t.Errorf("event %q command must not carry --enforce in monitor mode: %q", ev.settingsKey, ref.Command)
		}
		if ev.timeoutMs != 0 && ref.Timeout != ev.timeoutMs {
			t.Errorf("event %q timeout = %d, want %d (ms)", ev.settingsKey, ref.Timeout, ev.timeoutMs)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("settings.json perms = %o, want 600", perm)
	}
}

// auspex wires prompts, tool moments, assistant completion, and session boundaries.
func TestGeminiInstallWiresExactlyTheIngestedEvents(t *testing.T) {
	want := map[string]bool{
		"SessionStart": true, "BeforeAgent": true, "BeforeTool": true,
		"AfterTool": true, "AfterAgent": true, "SessionEnd": true,
	}
	if len(geminiHookEvents) != len(want) {
		t.Fatalf("geminiHookEvents has %d entries, want %d", len(geminiHookEvents), len(want))
	}
	for _, ev := range geminiHookEvents {
		if !want[ev.settingsKey] {
			t.Errorf("unexpected wired Gemini event %q", ev.settingsKey)
		}
	}
	// Events auspex must NOT wire (no clean lifecycle mapping).
	have := map[string]bool{}
	for _, ev := range geminiHookEvents {
		have[ev.settingsKey] = true
	}
	for _, unwired := range []string{"BeforeModel", "AfterModel", "BeforeToolSelection", "PreCompress", "Notification"} {
		if have[unwired] {
			t.Errorf("Gemini event %q should NOT be wired (auspex does not ingest it)", unwired)
		}
	}
}

func TestGeminiInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hooks := readGeminiHooks(t, path)
	if got, want := countGeminiAuspexHooks(hooks), len(geminiHookEvents); got != want {
		t.Fatalf("after two installs got %d auspex hooks, want %d (no duplicates)", got, want)
	}
}

func TestGeminiInstallPreservesUnrelatedKeysAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	// A pre-existing settings.json with an unrelated top-level key and a user-defined
	// BeforeTool hook auspex must not disturb.
	seed := map[string]any{
		"theme": "dark",
		"hooks": map[string]any{
			"BeforeTool": []any{
				map[string]any{
					"matcher": "run_shell_command",
					"hooks": []any{
						map[string]any{"name": "user-audit", "type": "command", "command": "/opt/user-audit shell"},
					},
				},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
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
	if _, ok := top["theme"]; !ok {
		t.Error("unrelated top-level key theme was dropped")
	}

	gs, err := readGeminiSettings(path)
	if err != nil {
		t.Fatalf("readGeminiSettings: %v", err)
	}
	foundUser := false
	for _, g := range gs.hooks["BeforeTool"] {
		for _, h := range g.Hooks {
			if h.Command == "/opt/user-audit shell" {
				foundUser = true
			}
		}
	}
	if !foundUser {
		t.Error("user's BeforeTool hook was dropped")
	}
	if countGeminiAuspexHooks(gs.hooks) != len(geminiHookEvents) {
		t.Errorf("auspex hooks = %d, want %d", countGeminiAuspexHooks(gs.hooks), len(geminiHookEvents))
	}
}

func TestGeminiInstallRoundTripPreservesUnknownHookFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"BeforeTool": []any{
				map[string]any{
					"matcher":        "run_shell_command",
					"groupExtension": "keep-group",
					"hooks": []any{
						map[string]any{
							"name": "user-audit", "type": "command", "command": "user-audit",
							"async": true, "extension": map[string]any{"enabled": true},
						},
					},
				},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertGeminiUnknownHookFields(t, path)
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	assertGeminiUnknownHookFields(t, path)
	if _, err := Uninstall(AgentGemini, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	assertGeminiUnknownHookFields(t, path)
}

func assertGeminiUnknownHookFields(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Hooks map[string][]map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	for _, group := range settings.Hooks["BeforeTool"] {
		if string(group["groupExtension"]) != `"keep-group"` {
			continue
		}
		var refs []map[string]json.RawMessage
		if err := json.Unmarshal(group["hooks"], &refs); err != nil {
			t.Fatal(err)
		}
		for _, ref := range refs {
			if string(ref["name"]) == `"user-audit"` && string(ref["async"]) == "true" &&
				rawExtensionEnabled(ref["extension"]) {
				return
			}
		}
	}
	t.Fatal("unknown Gemini hook and group fields were not preserved")
}

func TestGeminiUninstallRemovesOnlyAuspexHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"BeforeTool": []any{
				map[string]any{
					"matcher": "run_shell_command",
					"hooks": []any{
						map[string]any{"name": "user-audit", "type": "command", "command": "/opt/user-audit shell"},
					},
				},
			},
		},
	}
	writeJSON(t, path, seed)
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentGemini, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	gs, err := readGeminiSettings(path)
	if err != nil {
		t.Fatalf("readGeminiSettings: %v", err)
	}
	if countGeminiAuspexHooks(gs.hooks) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %+v", gs.hooks)
	}
	foundUser := false
	for _, g := range gs.hooks["BeforeTool"] {
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

// Uninstall leaves Gemini's required hooks map present, even when empty.
func TestGeminiUninstallLeavesValidSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(AgentGemini, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string][]geminiHookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("post-uninstall settings.json is not valid: %v (%s)", err, data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall file dropped the hooks map: %s", data)
	}
	if countGeminiAuspexHooks(readGeminiHooks(t, path)) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %s", data)
	}
}

func TestGeminiUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	rep, err := Uninstall(AgentGemini, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

func TestGeminiStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if rep := Status(AgentGemini, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentGemini, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestGeminiMalformedSettingsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err == nil {
		t.Error("Install on malformed settings.json should error rather than corrupt the file")
	}
}

// Detection keys on the auspex marker (the structured name="auspex" plus the
// command marker), not the binary path, so a binary with no "auspex" in its name
// still installs, reports installed, uninstalls cleanly, and reinstalls without
// duplicating entries.
func TestGeminiInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentGemini, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentGemini, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if got := countGeminiAuspexHooks(readGeminiHooks(t, path)); got != len(geminiHookEvents) {
		t.Fatalf("after install got %d hooks, want %d", got, len(geminiHookEvents))
	}
	if _, err := Install(AgentGemini, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if got := countGeminiAuspexHooks(readGeminiHooks(t, path)); got != len(geminiHookEvents) {
		t.Fatalf("after reinstall got %d hooks, want %d (no duplicates)", got, len(geminiHookEvents))
	}
	rep, err := Uninstall(AgentGemini, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if got := countGeminiAuspexHooks(readGeminiHooks(t, path)); got != 0 {
		t.Errorf("hooks remain after uninstall: %d", got)
	}
}

// The backup must preserve the pristine pre-auspex original across repeated
// install / install→uninstall→install cycles.
func TestGeminiBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = `{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"name":"keep","type":"command","command":"/opt/keep me"}]}]}}`
	check := func(t *testing.T, mutate func(path string)) {
		path := filepath.Join(t.TempDir(), "settings.json")
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
			if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentGemini, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// A pre-existing 0644 settings.json must be tightened to 0600 after an in-place
// rewrite, since it can carry tokens.
func TestGeminiInstallEnforces0600OnPreExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("settings.json perms after install = %o, want 600", perm)
	}
}

// When an output file is supplied, every installed command wires durable findings
// output so a hook-detected finding is not lost to stderr.
func TestGeminiInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentGemini, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	gs, err := readGeminiSettings(path)
	if err != nil {
		t.Fatalf("readGeminiSettings: %v", err)
	}
	n := 0
	for _, groups := range gs.hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if !isAuspexGeminiHook(h) {
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
	if n != len(geminiHookEvents) {
		t.Fatalf("wired %d auspex commands, want %d", n, len(geminiHookEvents))
	}
}

func TestGeminiEnforceInstallThreadsOnlyBeforeTool(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gemini", "settings.json")
	if _, err := Install(AgentGemini, path, auspexBinary, "", true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(hookCommandText(string(data)), enforceFlag); got != 1 {
		t.Fatalf("enforce flags = %d, want 1 in BeforeTool only\n%s", got, data)
	}
}

// GeminiSettingsPath defaults to ~/.gemini/settings.json. GEMINI_CLI_HOME
// replaces the user home, so .gemini remains in the resolved path.
// macOS-safe: assert on the trailing path segments (filepath.Base / Dir), not a
// full-path equality that a /var→/private/var symlink would break.
func TestGeminiSettingsPathHonorsGeminiHome(t *testing.T) {
	t.Setenv("GEMINI_CLI_HOME", "")
	def := GeminiSettingsPath("/home/u")
	if filepath.Base(def) != "settings.json" {
		t.Errorf("default path base = %q, want settings.json", filepath.Base(def))
	}
	if filepath.Base(filepath.Dir(def)) != ".gemini" {
		t.Errorf("default path parent = %q, want .gemini", filepath.Base(filepath.Dir(def)))
	}

	custom := t.TempDir()
	t.Setenv("GEMINI_CLI_HOME", custom)
	got := GeminiSettingsPath("/home/u")
	if filepath.Base(got) != "settings.json" {
		t.Errorf("GEMINI_CLI_HOME path base = %q, want settings.json", filepath.Base(got))
	}
	if filepath.Base(filepath.Dir(got)) != ".gemini" {
		t.Errorf("GEMINI_CLI_HOME path parent = %q, want .gemini", filepath.Dir(got))
	}
	if filepath.Dir(filepath.Dir(got)) != custom {
		t.Errorf("GEMINI_CLI_HOME base = %q, want %q", filepath.Dir(filepath.Dir(got)), custom)
	}
}

func TestGeminiSettingsPathPreservesSpaces(t *testing.T) {
	root := filepath.Join(t.TempDir(), " gemini home ")
	t.Setenv("GEMINI_CLI_HOME", root)
	want := filepath.Join(root, ".gemini", "settings.json")
	if got := GeminiSettingsPath("/unused/home"); got != want {
		t.Fatalf("GeminiSettingsPath = %q, want %q", got, want)
	}
}

// An install through the GEMINI_CLI_HOME-resolved path round-trips: the file lands
// under the override root and reports installed.
func TestGeminiInstallUnderGeminiHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GEMINI_CLI_HOME", root)
	path := GeminiSettingsPath("/unused/home")
	if _, err := Install(AgentGemini, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentGemini, path); !rep.Installed {
		t.Fatalf("status after install under GEMINI_CLI_HOME = not-installed")
	}
	// macOS-safe: compare stable trailing segments, not the full path — a
	// /var→/private/var symlink would break a full-path equality even though the
	// install landed in the right place. The file must be named settings.json and
	// sit under the .gemini directory beneath GEMINI_CLI_HOME.
	if filepath.Base(path) != "settings.json" {
		t.Errorf("install path base = %q, want settings.json", filepath.Base(path))
	}
	if filepath.Dir(filepath.Dir(path)) != root {
		t.Errorf("install path base = %q, want GEMINI_CLI_HOME %q", filepath.Dir(filepath.Dir(path)), root)
	}
}
