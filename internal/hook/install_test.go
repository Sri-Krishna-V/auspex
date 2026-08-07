package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func topKeys(top map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(top))
	for key := range top {
		keys = append(keys, key)
	}
	return keys
}

const auspexBinary = "/usr/local/bin/auspex"

// readHooks loads the "hooks" block from a settings file for assertions.
func readHooks(t *testing.T, path string) map[string][]hookGroup {
	t.Helper()
	sf, err := readSettings(path)
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	return sf.hooks
}

// countAuspexHooks counts auspex-installed command hooks across all events.
func countAuspexHooks(hooks map[string][]hookGroup) int {
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

func hookRefText(ref hookRef) string {
	return strings.Join(append([]string{hookCommandText(ref.Command)}, ref.Args...), " ")
}

func modeMatches(got, want os.FileMode) bool {
	return runtime.GOOS == "windows" || got == want
}

func TestSamePlatformPath(t *testing.T) {
	a := filepath.Join(`C:\Users\Alice`, ".Hermes", "config.yaml")
	b := filepath.Join(`c:\users\alice`, ".hermes", "config.yaml")
	if !samePlatformPathForOS(a, b, "windows") {
		t.Fatalf("Windows paths should compare case-insensitively: %q, %q", a, b)
	}
	if samePlatformPathForOS(a, b, "linux") {
		t.Fatalf("Unix paths should remain case-sensitive: %q, %q", a, b)
	}
}

func TestClaudeSettingsPathHonorsConfigDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "claude config")
	t.Setenv("CLAUDE_CONFIG_DIR", root)
	if got, want := ClaudeSettingsPath("/unused"), filepath.Join(root, "settings.json"); got != want {
		t.Fatalf("ClaudeSettingsPath = %q, want %q", got, want)
	}
}

func TestInstallCreatesAllLifecycleHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	rep, err := Install(AgentClaude, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want installed+changed", rep)
	}
	hooks := readHooks(t, path)
	if got, want := countAuspexHooks(hooks), len(claudeHookEvents); got != want {
		t.Fatalf("installed %d auspex hooks, want one per lifecycle (%d)", got, want)
	}
	// The file must be 0600 since settings can carry tokens.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("settings perms = %o, want 600", perm)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hooks := readHooks(t, path)
	if got, want := countAuspexHooks(hooks), len(claudeHookEvents); got != want {
		t.Fatalf("after two installs got %d auspex hooks, want %d (no duplicates)", got, want)
	}
}

func TestInstallPreservesUnrelatedSettingsAndHooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// A pre-existing settings file with an unrelated top-level key and a
	// user-defined PreToolUse hook that auspex must not disturb.
	seed := map[string]any{
		"model": "opus",
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks":   []any{map[string]any{"type": "command", "command": "/opt/user-audit pre"}},
				},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	sf, err := readSettings(path)
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	if string(sf.values["model"]) != `"opus"` {
		t.Errorf("unrelated key model not preserved: %s", sf.values["model"])
	}
	// The user's audit hook must still be present alongside auspex's pre-tool hook.
	foundUser := false
	for _, g := range sf.hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if h.Command == "/opt/user-audit pre" {
				foundUser = true
			}
		}
	}
	if !foundUser {
		t.Error("user's PreToolUse hook was dropped")
	}
	if countAuspexHooks(sf.hooks) != len(claudeHookEvents) {
		t.Errorf("auspex hooks = %d, want %d", countAuspexHooks(sf.hooks), len(claudeHookEvents))
	}
}

func TestClaudeInstallRoundTripPreservesUnknownHookFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher":        "Bash",
					"groupExtension": "keep-group",
					"hooks": []any{
						map[string]any{"type": "http", "url": "https://audit.example/hook", "async": true},
						map[string]any{
							"type": "command", "command": "user-audit", "args": []string{"a b"},
							"shell": "powershell", "extension": map[string]any{"enabled": true},
						},
					},
				},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertClaudeUnknownHookFields(t, path)
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	assertClaudeUnknownHookFields(t, path)
	if _, err := Uninstall(AgentClaude, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	assertClaudeUnknownHookFields(t, path)
}

func assertClaudeUnknownHookFields(t *testing.T, path string) {
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
	for _, group := range settings.Hooks["PreToolUse"] {
		if string(group["groupExtension"]) != `"keep-group"` {
			continue
		}
		var refs []map[string]json.RawMessage
		if err := json.Unmarshal(group["hooks"], &refs); err != nil {
			t.Fatal(err)
		}
		var keptHTTP, keptCommand bool
		for _, ref := range refs {
			switch string(ref["type"]) {
			case `"http"`:
				keptHTTP = string(ref["url"]) == `"https://audit.example/hook"` && string(ref["async"]) == "true"
			case `"command"`:
				keptCommand = string(ref["command"]) == `"user-audit"` &&
					string(ref["shell"]) == `"powershell"` && rawExtensionEnabled(ref["extension"])
			}
		}
		if keptHTTP && keptCommand {
			return
		}
	}
	t.Fatal("unknown hook and group fields were not preserved")
}

func rawExtensionEnabled(raw json.RawMessage) bool {
	var extension struct {
		Enabled bool `json:"enabled"`
	}
	return json.Unmarshal(raw, &extension) == nil && extension.Enabled
}

func TestInstallBacksUpExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeJSON(t, path, map[string]any{"model": "sonnet"})
	rep, err := Install(AgentClaude, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep.BackupPath == "" {
		t.Fatal("expected a backup path for an existing file")
	}
	data, err := os.ReadFile(rep.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !strings.Contains(string(data), "sonnet") {
		t.Errorf("backup missing original content: %s", data)
	}
}

func TestInstallRejectsNonRegularExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeJSON(t, path, map[string]any{"model": "sonnet"})
	if err := os.Mkdir(path+backupSuffix, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err == nil ||
		!strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("Install error = %v, want non-regular backup rejection", err)
	}
}

func TestReinstallDoesNotBackUpAuspexCreatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path + backupSuffix); !os.IsNotExist(err) {
		t.Fatalf("reinstall created a backup of auspex-owned content: %v", err)
	}
}

func TestUninstallRemovesOnlyAuspexHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks":   []any{map[string]any{"type": "command", "command": "/opt/user-audit pre"}},
				},
			},
		},
	}
	writeJSON(t, path, seed)
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentClaude, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	hooks := readHooks(t, path)
	if countAuspexHooks(hooks) != 0 {
		t.Errorf("auspex hooks remain after uninstall: %+v", hooks)
	}
	// The user's hook survives.
	foundUser := false
	for _, g := range hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if h.Command == "/opt/user-audit pre" {
				foundUser = true
			}
		}
	}
	if !foundUser {
		t.Error("uninstall removed the user's unrelated hook")
	}
}

func TestUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	rep, err := Uninstall(AgentClaude, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

func TestStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if rep := Status(AgentClaude, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentClaude, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestUnsupportedAgentsAreHonest(t *testing.T) {
	// Every agent auspex targets now has a hook integration, so an unsupported
	// report is reached only for an UNKNOWN agent id. Such an install must make no
	// change and name the
	// agent it could not wire.
	for _, agent := range []string{"definitely-not-an-agent"} {
		rep, err := Install(agent, "/unused", auspexBinary, "", false)
		if err != nil {
			t.Fatalf("Install(%s): %v", agent, err)
		}
		if rep.Supported {
			t.Errorf("%s should be reported unsupported", agent)
		}
		if rep.Installed || rep.Changed {
			t.Errorf("%s must not be installed", agent)
		}
		if !strings.Contains(rep.Message, agent) {
			t.Errorf("%s message should name the unknown agent: %q", agent, rep.Message)
		}
	}
}

func TestMalformedSettingsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err == nil {
		t.Error("Install on malformed settings should error rather than corrupt the file")
	}
}

// Regression: os.WriteFile only sets mode on create, so a pre-existing 0644
// settings file would keep 0644 after an in-place rewrite. Install must enforce
// 0600 regardless of the pre-existing mode, since the file can carry tokens.
func TestInstallEnforces0600OnPreExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"model":"opus"}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if info, _ := os.Stat(path); !modeMatches(info.Mode().Perm(), 0o644) {
		t.Fatalf("seed perms = %o, want 644", info.Mode().Perm())
	}
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("settings perms after install = %o, want 600 on a pre-existing 0644 file", perm)
	}
}

// Regression: detection must key on a marker auspex owns, not on the binary path
// literally containing "auspex". A binary at a path with no "auspex" in it must
// still install, report installed, uninstall cleanly, and reinstall without
// duplicating hooks.
func TestInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch" // deliberately no "auspex" substring
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "settings.json")

	if _, err := Install(AgentClaude, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentClaude, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if got := countAuspexHooks(readHooks(t, path)); got != len(claudeHookEvents) {
		t.Fatalf("after install got %d hooks, want %d", got, len(claudeHookEvents))
	}

	// Reinstall must not duplicate.
	if _, err := Install(AgentClaude, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if got := countAuspexHooks(readHooks(t, path)); got != len(claudeHookEvents) {
		t.Fatalf("after reinstall got %d hooks, want %d (no duplicates)", got, len(claudeHookEvents))
	}

	// Uninstall must remove exactly auspex's entries.
	rep, err := Uninstall(AgentClaude, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change for a renamed-binary install")
	}
	if got := countAuspexHooks(readHooks(t, path)); got != 0 {
		t.Errorf("hooks remain after uninstall: %d", got)
	}
}

// Regression: the backup must preserve the pristine pre-auspex original. A fixed
// .auspex-bak that is overwritten on every write would capture already-modified
// content on the second install (or after an uninstall), making the original
// unrecoverable. Install twice, and install→uninstall→install, then assert the
// pristine original is still recoverable from the backup.
func TestBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = `{"model":"pristine-original"}`
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
		if !strings.Contains(string(data), "pristine-original") {
			t.Fatalf("backup is not the pristine original: %s", data)
		}
	}

	t.Run("install twice", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})

	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentClaude, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// Non-blocking (a): when an output file is supplied, every installed command
// wires durable findings output (--output=file) so a hook-detected finding is
// not lost to stderr. The marker still tags the command for detection.
func TestInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentClaude, path, auspexBinary, out, false); err != nil {
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
				command := hookRefText(h)
				if !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
					t.Errorf("command missing durable output wiring: %q", command)
				}
			}
		}
	}
	if n != len(claudeHookEvents) {
		t.Fatalf("wired %d auspex commands, want %d", n, len(claudeHookEvents))
	}
	// An empty output file leaves the command without output flags (opt-out).
	path2 := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentClaude, path2, auspexBinary, "", false); err != nil {
		t.Fatalf("Install (no output): %v", err)
	}
	sf2, _ := readSettings(path2)
	for _, groups := range sf2.hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isAuspexHookRef(h) && strings.Contains(hookRefText(h), "--output=file") {
					t.Errorf("command should have no output wiring when outputFile is empty: %q", hookRefText(h))
				}
			}
		}
	}
}

func TestInstallWiresClaudeBoundaryAndFailureHooks(t *testing.T) {
	pre := findClaudeHookEvent("PreToolUse")
	if pre == nil {
		t.Fatal("claudeHookEvents has no PreToolUse entry")
		return
	}
	if pre.matcher != "" {
		t.Errorf("PreToolUse matcher = %q, want omitted matcher for all tools", pre.matcher)
	}

	want := map[string]string{
		"PostToolUseFailure": "post-tool",
		"PermissionDenied":   "permission-denied",
		"Stop":               "stop",
		"SubagentStart":      "session-start",
		"SubagentStop":       "session-end",
	}
	for event, lifecycle := range want {
		entry := findClaudeHookEvent(event)
		if entry == nil {
			t.Fatalf("claudeHookEvents has no %s entry", event)
			return
		}
		if entry.lifecycle != lifecycle {
			t.Errorf("%s lifecycle = %q, want %q", event, entry.lifecycle, lifecycle)
		}
	}

	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	hooks := readHooks(t, path)
	for event, lifecycle := range want {
		groups := hooks[event]
		found := false
		for _, g := range groups {
			for _, h := range g.Hooks {
				if !isAuspexHookRef(h) {
					continue
				}
				found = true
				if !strings.Contains(hookRefText(h), "hook "+lifecycle+" ") {
					t.Errorf("%s command does not invoke %s: %q", event, lifecycle, hookRefText(h))
				}
			}
		}
		if !found {
			t.Fatalf("no auspex-installed %s hook command found", event)
		}
	}
}

func TestReadSettingsRejectsOversizeConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxHookConfigFileSize + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readSettings(path); err == nil || !strings.Contains(err.Error(), "hook config exceeds") {
		t.Fatalf("readSettings error = %v, want size-limit error", err)
	}
}

func TestInstallRejectsSymlinkedConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	target := filepath.Join(t.TempDir(), "target.json")
	const original = `{"theme":"dark"}`
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentClaude, path, auspexBinary, "", false); err == nil {
		t.Fatal("Install accepted a symlinked hook config")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("symlink target changed: %s", got)
	}
}

func findClaudeHookEvent(event string) *claudeHookEvent {
	for i := range claudeHookEvents {
		if claudeHookEvents[i].settingsKey == event {
			return &claudeHookEvents[i]
		}
	}
	return nil
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
