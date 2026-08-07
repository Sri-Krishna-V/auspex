package hook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Factory's standalone hooks.json is a top-level event map. The nested
// {"hooks": ...} shape belongs only in settings.json.
func readFactoryHooks(t *testing.T, path string) map[string][]hookGroup {
	t.Helper()
	ff, err := readFactoryHooksFile(path)
	if err != nil {
		t.Fatalf("read Factory hooks file %s: %v", path, err)
	}
	return ff.hooks
}

func TestFactoryInstallWritesEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".factory", "hooks.json")
	rep, err := Install(AgentFactory, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}

	hooks := readFactoryHooks(t, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if _, nested := wire["hooks"]; nested {
		t.Fatalf("canonical hooks.json must not use nested settings shape: %s", data)
	}
	wantEvents := []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStop", "SessionEnd"}
	if len(hooks) != len(wantEvents) {
		t.Fatalf("hooks block has %d events, want %d: %v", len(hooks), len(wantEvents), hooks)
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
		if !strings.Contains(command, "--agent factory") {
			t.Errorf("event %q command must target --agent factory: %q", ev, h.Command)
		}
		// Monitor mode must not thread the enforcement flag.
		if strings.Contains(command, "--enforce") {
			t.Errorf("event %q command must not carry --enforce: %q", ev, h.Command)
		}
	}

	// An omitted matcher covers every tool and avoids pinning a vendor-specific
	// wildcard spelling.
	post := hooks["PostToolUse"][0]
	if post.Matcher != "" {
		t.Errorf("PostToolUse matcher = %q, want omitted", post.Matcher)
	}
	if !strings.Contains(hookCommandText(post.Hooks[0].Command), string(LifecycleFactoryPostTool)) {
		t.Errorf("PostToolUse command must invoke %q: %q", LifecycleFactoryPostTool, post.Hooks[0].Command)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks.json perms = %o, want 600", perm)
	}
}

// TestFactoryInstallIsIdempotent: a second install yields byte-identical content
// (auspex's group is rebuilt fresh, never duplicated) and reports installed.
func TestFactoryInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("re-install produced different content:\n%s\n---\n%s", first, second)
	}
	if rep := Status(AgentFactory, path); !rep.Installed {
		t.Error("status after re-install should be installed")
	}
}

// TestFactoryInstallWiresDurableOutputFile: when an output file is supplied, the
// wired command threads --output=file and the path so a hook-detected finding is not
// lost to stderr.
func TestFactoryInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentFactory, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	hooks := readFactoryHooks(t, path)
	cmd := hooks["PostToolUse"][0].Hooks[0].Command
	if command := hookCommandText(cmd); !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
		t.Errorf("command missing durable output wiring: %q", cmd)
	}
}

// TestFactoryInstallPreservesForeignSettings: an unrelated top-level key
// and an unrelated hook are preserved across install and uninstall — auspex only
// ever touches its own marked groups.
func TestFactoryInstallPreservesForeignSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const seeded = `{"x-factory-metadata":{"model":"droid-1"},"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo hi"}]}]}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
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
	if _, ok := top["x-factory-metadata"]; !ok {
		t.Errorf("foreign top-level key dropped on install: %s", data)
	}
	if !strings.Contains(string(data), "echo hi") {
		t.Errorf("foreign hook dropped on install: %s", data)
	}

	// Uninstall must remove ONLY auspex's hooks and leave the foreign ones intact.
	rep, err := Uninstall(AgentFactory, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if rep := Status(AgentFactory, path); rep.Installed {
		t.Error("status after uninstall should be not-installed")
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if !strings.Contains(string(data), "echo hi") {
		t.Errorf("foreign hook removed on uninstall: %s", data)
	}
	if !strings.Contains(string(data), "droid-1") {
		t.Errorf("foreign top-level key removed on uninstall: %s", data)
	}
	if strings.Contains(hookCommandText(string(data)), auspexHookMarker) {
		t.Errorf("auspex marker survived uninstall: %s", data)
	}
}

func TestFactoryJSONCHooksInstallStatusAndUninstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const seeded = `{
  // Factory accepts comments in its standalone hook file.
  "x-factory-metadata": {
    "endpoint": "https://example.com/path/*glob*/",
    "features": ["foreign",],
  },
  "PostToolUse": [
    {
      "matcher": "*",
      "x-group": {"keep": true,},
      "hooks": [
        {
          "type": "command",
          "command": "printf 'https://example.com/path/*glob*/'",
          "timeout": 1.25,
          "x-ref": ["keep",],
        },
      ],
    },
  ],
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed JSONC: %v", err)
	}

	rep, err := Install(AgentFactory, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install on JSONC hooks.json: %v", err)
	}
	if !rep.Installed || !rep.Changed {
		t.Fatalf("install report = %+v, want installed+changed", rep)
	}
	backup, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatalf("read pristine JSONC backup: %v", err)
	}
	if string(backup) != seeded {
		t.Errorf("backup did not preserve original comments and formatting:\n%s", backup)
	}

	ff, err := readFactoryHooksFile(path)
	if err != nil {
		t.Fatalf("read installed hooks: %v", err)
	}
	var metadata struct {
		Endpoint string   `json:"endpoint"`
		Features []string `json:"features"`
	}
	if err := json.Unmarshal(ff.values["x-factory-metadata"], &metadata); err != nil {
		t.Fatalf("decode foreign metadata: %v", err)
	}
	if metadata.Endpoint != "https://example.com/path/*glob*/" || len(metadata.Features) != 1 || metadata.Features[0] != "foreign" {
		t.Errorf("foreign JSONC value changed: %+v", metadata)
	}
	foreign := ff.hooks["PostToolUse"][0]
	if _, ok := foreign.fields["x-group"]; !ok {
		t.Fatalf("foreign group field lost: %+v", foreign)
	}
	if len(foreign.Hooks) != 1 {
		t.Fatalf("foreign PostToolUse group changed: %+v", foreign)
	}
	if _, ok := foreign.Hooks[0].fields["x-ref"]; !ok {
		t.Errorf("foreign hook-ref field lost: %+v", foreign.Hooks[0])
	}
	if got := foreign.Hooks[0].fields["timeout"]; string(got) != "1.25" {
		t.Errorf("foreign fractional timeout = %s, want 1.25", got)
	}
	if status := Status(AgentFactory, path); !status.Installed {
		t.Fatalf("status after JSONC install = %+v, want installed", status)
	}

	uninstall, err := Uninstall(AgentFactory, path)
	if err != nil {
		t.Fatalf("Uninstall JSONC-derived hooks: %v", err)
	}
	if !uninstall.Changed {
		t.Fatalf("uninstall report = %+v, want changed", uninstall)
	}
	ff, err = readFactoryHooksFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if ff.hasAuspexHooks() {
		t.Error("auspex marker survived uninstall")
	}
	if _, ok := ff.values["x-factory-metadata"]; !ok {
		t.Error("foreign metadata lost on uninstall")
	}
	groups := ff.hooks["PostToolUse"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || !strings.Contains(groups[0].Hooks[0].Command, "https://example.com/path/*glob*/") {
		t.Errorf("foreign PostToolUse hook lost on uninstall: %+v", groups)
	}
}

func TestFactoryStatusReadsJSONCWithoutRewritingComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const seeded = `{
  /* status is read-only */
  "x-note": "https://example.com/*literal*/",
  "SessionStart": [
    {
      "hooks": [
        {"type": "command", "command": "echo foreign",},
      ],
    },
    {
      "hooks": [
        {"type": "command", "command": "/opt/sensor hook session-start --installed-by=auspex",},
      ],
    },
  ],
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed JSONC: %v", err)
	}
	status, err := StatusErr(AgentFactory, path)
	if err != nil {
		t.Fatalf("StatusErr on JSONC hooks.json: %v", err)
	}
	if !status.Installed {
		t.Fatalf("status = %+v, want installed", status)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after status: %v", err)
	}
	if string(after) != seeded {
		t.Errorf("read-only status rewrote comments or formatting:\n%s", after)
	}
	uninstall, err := Uninstall(AgentFactory, path)
	if err != nil || !uninstall.Changed {
		t.Fatalf("direct uninstall from JSONC = %+v, err %v", uninstall, err)
	}
	ff, err := readFactoryHooksFile(path)
	if err != nil {
		t.Fatalf("read direct uninstall output: %v", err)
	}
	groups := ff.hooks["SessionStart"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != "echo foreign" {
		t.Errorf("direct JSONC uninstall did not preserve foreign hook: %+v", groups)
	}
	var note string
	if err := json.Unmarshal(ff.values["x-note"], &note); err != nil || note != "https://example.com/*literal*/" {
		t.Errorf("direct JSONC uninstall changed string literal: %q, err %v", note, err)
	}
}

func TestFactoryJSONCSettingsInstallAndUninstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".factory", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const seeded = `{
  // Unrelated Factory settings must survive the hooks edit.
  "model": {"name": "droid", "endpoint": "https://example.com/api/*",},
  "hooks": {
    "Notification": [
      {"hooks": [{"type": "command", "command": "echo foreign",},],},
    ],
  },
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed settings JSONC: %v", err)
	}
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install on JSONC settings.json: %v", err)
	}
	status, err := StatusErr(AgentFactory, path)
	if err != nil || !status.Installed {
		t.Fatalf("status after settings install = %+v, err %v", status, err)
	}
	sf, err := readFactorySettings(path)
	if err != nil {
		t.Fatalf("read installed settings: %v", err)
	}
	if _, ok := sf.values["model"]; !ok {
		t.Error("foreign model setting lost")
	}
	groups := sf.hooks.hooks["Notification"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != "echo foreign" {
		t.Errorf("foreign settings hook lost: %+v", groups)
	}
	backup, err := os.ReadFile(path + backupSuffix)
	if err != nil || string(backup) != seeded {
		t.Errorf("settings backup did not preserve JSONC bytes: err=%v data=%s", err, backup)
	}
	if _, err := Uninstall(AgentFactory, path); err != nil {
		t.Fatalf("Uninstall settings: %v", err)
	}
	sf, err = readFactorySettings(path)
	if err != nil {
		t.Fatalf("read uninstalled settings: %v", err)
	}
	if sf.hasAuspexHooks() {
		t.Error("auspex hooks survived settings uninstall")
	}
	if _, ok := sf.values["model"]; !ok {
		t.Error("foreign model setting lost on uninstall")
	}
	groups = sf.hooks.hooks["Notification"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != "echo foreign" {
		t.Errorf("foreign settings hook lost on uninstall: %+v", groups)
	}
}

func TestFactoryJSONCSettingsDirectUninstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	const seeded = `{
  // Uninstall must parse the original JSONC, not only auspex-generated JSON.
  "model": "droid",
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "echo foreign",},],},
      {"hooks": [{"type": "command", "command": "/opt/sensor hook session-start --installed-by=auspex",},],},
    ],
  },
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed JSONC settings: %v", err)
	}
	rep, err := Uninstall(AgentFactory, path)
	if err != nil || !rep.Changed {
		t.Fatalf("direct settings uninstall = %+v, err %v", rep, err)
	}
	sf, err := readFactorySettings(path)
	if err != nil {
		t.Fatalf("read direct settings uninstall output: %v", err)
	}
	groups := sf.hooks.hooks["SessionStart"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != "echo foreign" {
		t.Errorf("direct settings uninstall did not preserve foreign hook: %+v", groups)
	}
	var modelName string
	if err := json.Unmarshal(sf.values["model"], &modelName); err != nil || modelName != "droid" {
		t.Errorf("foreign model changed: %q, err %v", modelName, err)
	}
}

func TestFactoryInstallMigratesJSONCLegacySources(t *testing.T) {
	home := t.TempDir()
	canonicalPath := filepath.Join(home, ".factory", "hooks.json")
	legacyPath := filepath.Join(home, ".factory", "hooks", "hooks.json")
	settingsPath := filepath.Join(home, ".factory", "settings.json")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const legacySeed = `{
  // The old standalone source is active until root hooks.json is created.
  "x-legacy": {"url": "https://legacy.example/*path*/",},
  "Notification": [
    {"hooks": [{"type": "command", "command": "echo legacy",},],},
  ],
}`
	const settingsSeed = `{
  /* Root SessionStart will override this event, so it must be carried forward. */
  "theme": "dark",
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "echo settings",},],},
    ],
  },
}`
	if err := os.WriteFile(legacyPath, []byte(legacySeed), 0o600); err != nil {
		t.Fatalf("seed legacy JSONC: %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte(settingsSeed), 0o600); err != nil {
		t.Fatalf("seed settings JSONC: %v", err)
	}

	rep, err := Install(AgentFactory, canonicalPath, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("migrate JSONC sources: %v", err)
	}
	if !strings.Contains(rep.Message, "migrated legacy") || !strings.Contains(rep.Message, "preserved settings.json") {
		t.Errorf("migration report missing source details: %+v", rep)
	}
	ff, err := readFactoryHooksFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical migration output: %v", err)
	}
	if _, ok := ff.values["x-legacy"]; !ok {
		t.Error("legacy foreign top-level field was not migrated")
	}
	legacyGroups := ff.hooks["Notification"]
	if len(legacyGroups) != 1 || len(legacyGroups[0].Hooks) != 1 || legacyGroups[0].Hooks[0].Command != "echo legacy" {
		t.Errorf("legacy foreign hook was not migrated: %+v", legacyGroups)
	}
	sessionGroups := ff.hooks["SessionStart"]
	foundSettings := false
	for _, group := range sessionGroups {
		for _, ref := range group.Hooks {
			foundSettings = foundSettings || ref.Command == "echo settings"
		}
	}
	if !foundSettings || !hasAuspexGroup(sessionGroups) {
		t.Errorf("canonical SessionStart did not preserve settings and add auspex: %+v", sessionGroups)
	}
	for path, want := range map[string]string{legacyPath: legacySeed, settingsPath: settingsSeed} {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read unchanged source %s: %v", path, readErr)
			continue
		}
		if string(got) != want {
			t.Errorf("migration rewrote unmodified JSONC source %s:\n%s", path, got)
		}
	}
}

func TestFactoryJSONCInvalidInputFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		data     string
	}{
		{"hooks unterminated comment", "hooks.json", `{"x": 1, /* never closed`},
		{"hooks missing array value", "hooks.json", `{"x": [,],}`},
		{"hooks comment cannot join tokens", "hooks.json", `{"x": 1/* gap */2}`},
		{"settings unterminated comment", "settings.json", `{"theme": "dark", /* never closed`},
		{"settings missing array value", "settings.json", `{"x": [,],}`},
		{"settings comment cannot join tokens", "settings.json", `{"x": 1/* gap */2}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatalf("seed malformed JSONC: %v", err)
			}
			if _, err := Install(AgentFactory, path, auspexBinary, "", false); err == nil {
				t.Error("Install accepted malformed JSONC")
			}
			if _, err := StatusErr(AgentFactory, path); err == nil {
				t.Error("StatusErr accepted malformed JSONC")
			}
			if _, err := Uninstall(AgentFactory, path); err == nil {
				t.Error("Uninstall accepted malformed JSONC")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read after rejected operations: %v", err)
			}
			if string(got) != tc.data {
				t.Errorf("malformed source was changed:\n%s", got)
			}
			if _, err := os.Lstat(path + backupSuffix); !os.IsNotExist(err) {
				t.Errorf("rejected input created a backup: %v", err)
			}
		})
	}
}

// A pre-existing settings file is backed up once before it is changed.
func TestFactoryBackupPreservesPristineOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const pristine = `{"x-factory-metadata":"keep me"}`
	if err := os.WriteFile(path, []byte(pristine), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
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

// TestFactoryDetectionIsRenameProof: detection keys on auspex's marker, not the
// binary path, so a binary with no "auspex" in its name still installs, reports
// installed, and uninstalls cleanly.
func TestFactoryDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentFactory, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentFactory, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	rep, err := Uninstall(AgentFactory, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
}

// Uninstalling when no settings file exists is a clean no-op.
func TestFactoryUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "hooks.json")
	rep, err := Uninstall(AgentFactory, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

// TestFactoryStatusReflectsInstallState: status is not-installed before install,
// installed after.
func TestFactoryStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if rep := Status(AgentFactory, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentFactory, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestFactoryEnforceInstallThreadsOnlyPreTool(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".factory", "hooks.json")
	if _, err := Install(AgentFactory, path, auspexBinary, "", true); err != nil {
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

func TestFactorySettingsPath(t *testing.T) {
	home := t.TempDir()
	want := filepath.Join(home, ".factory", "hooks.json")
	if got := FactorySettingsPath(home); got != want {
		t.Errorf("FactorySettingsPath = %q, want canonical root %q", got, want)
	}
}

func TestFactoryCanonicalAndSettingsWireShapes(t *testing.T) {
	t.Run("canonical hooks file uses top-level events", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "stage", "hooks.json")
		// A staging sibling must remain untouched: --settings is an exact path
		// selector, not permission to migrate adjacent files outside .factory.
		sibling := filepath.Join(filepath.Dir(path), "settings.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		const siblingBody = `{"hooks":{"PreToolUse":[]},"keep":true}`
		if err := os.WriteFile(sibling, []byte(siblingBody), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatal(err)
		}
		if _, ok := top["PreToolUse"]; !ok {
			t.Fatalf("canonical file lacks top-level event: %s", data)
		}
		if _, nested := top["hooks"]; nested {
			t.Fatalf("canonical file used nested settings shape: %s", data)
		}
		after, err := os.ReadFile(sibling)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != siblingBody {
			t.Fatalf("staging install rewrote sibling settings.json: %s", after)
		}
	})

	t.Run("explicit settings file keeps nested hooks", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".factory", "settings.json")
		if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatal(err)
		}
		if _, ok := top["hooks"]; !ok {
			t.Fatalf("settings.json lacks nested hooks object: %s", data)
		}
		if _, topLevel := top["PreToolUse"]; topLevel {
			t.Fatalf("settings.json contains canonical top-level event: %s", data)
		}
	})
}

func TestFactoryHooksPathCaseRules(t *testing.T) {
	if !factoryHooksPathForOS("C:/repo/.factory/HOOKS.JSON", "windows") {
		t.Fatal("Windows canonical hooks path should be case-insensitive")
	}
	if factoryHooksPathForOS("/repo/.factory/HOOKS.JSON", "darwin") {
		t.Fatal("POSIX canonical hooks path should preserve case-sensitive vendor name")
	}
}

func TestFactoryExplicitShadowedPathsDoNotOverstateCoverage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	root := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	settings := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte(`{"PreToolUse":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const dormant = `{"PreToolUse":[{"hooks":[{"type":"command","command":"watch --installed-by=auspex"}]}]}`
	if err := os.WriteFile(legacy, []byte(dormant), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"watch --installed-by=auspex"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(AgentFactory, legacy, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("install at shadowed legacy path error = %v, want actionable root path", err)
	}
	legacyStatus := Status(AgentFactory, legacy)
	if legacyStatus.Installed || !strings.Contains(legacyStatus.Message, "shadowed") {
		t.Fatalf("legacy status = %+v, want inactive/shadowed", legacyStatus)
	}

	if _, err := Install(AgentFactory, settings, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("install at partly shadowed settings path error = %v, want actionable root path", err)
	}
	settingsStatus := Status(AgentFactory, settings)
	if settingsStatus.Installed || !strings.Contains(settingsStatus.Message, "shadowed") {
		t.Fatalf("settings status = %+v, want inactive/shadowed", settingsStatus)
	}
}

func TestFactoryExplicitLegacyUninstallRefusesWhenRootIsActive(t *testing.T) {
	factoryDir := filepath.Join(t.TempDir(), ".factory")
	rootPath := filepath.Join(factoryDir, "hooks.json")
	legacyPath := filepath.Join(factoryDir, "hooks", "hooks.json")
	if _, err := Install(AgentFactory, rootPath, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, legacyPath, map[string]any{
		"PreToolUse": []hookGroup{{
			Hooks: []hookRef{{Type: "command", Command: "echo legacy"}},
		}},
	})

	if _, err := Uninstall(AgentFactory, legacyPath); err == nil ||
		!strings.Contains(err.Error(), "uninstall using --settings "+rootPath) {
		t.Fatalf("legacy uninstall error = %v, want active-root guidance", err)
	}
	if rep := Status(AgentFactory, rootPath); !rep.Installed {
		t.Fatalf("refused legacy uninstall changed active root: %+v", rep)
	}
}

func TestFactoryExplicitSettingsRejectsLegacyStandaloneShadow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	settings := filepath.Join(dir, "settings.json")
	root := filepath.Join(dir, "hooks.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"PostToolUse":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentFactory, settings, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("settings install error = %v, want canonical migration guidance", err)
	}
}

func TestFactoryExplicitSettingsStatusErrValidatesSelectedStandalone(t *testing.T) {
	for _, selected := range []string{"root", "legacy"} {
		t.Run(selected, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), ".factory")
			settings := filepath.Join(dir, "settings.json")
			selectedPath := filepath.Join(dir, "hooks.json")
			if selected == "legacy" {
				selectedPath = filepath.Join(dir, "hooks", "hooks.json")
			}
			if err := os.MkdirAll(filepath.Dir(selectedPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(selectedPath, []byte(`{"PreToolUse":`), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := StatusErr(AgentFactory, settings); err == nil {
				t.Fatalf("StatusErr should reject malformed selected %s standalone", selected)
			}
		})
	}
}

func TestFactorySettingsLocalIsNotClaimedAsHookSource(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	local := filepath.Join(dir, "settings.local.json")
	root := filepath.Join(dir, "hooks.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const config = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"watch --installed-by=auspex"}]}]}}`
	if err := os.WriteFile(local, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(AgentFactory, local, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("settings.local install error = %v, want canonical hook guidance", err)
	}
	status := Status(AgentFactory, local)
	if status.Installed || !strings.Contains(status.Message, "does not load hooks") || !strings.Contains(status.Message, "inactive") {
		t.Fatalf("settings.local status = %+v, want inactive source warning", status)
	}
}

func TestFactoryHooksDisabledIsEffectiveAndNotOverwritten(t *testing.T) {
	t.Run("standalone disables install and status", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".factory", "hooks.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		const config = `{"hooksDisabled":true,"showHookOutput":true,"PreToolUse":[{"hooks":[{"type":"command","command":"watch --installed-by=auspex"}]}]}`
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(AgentFactory, path, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), "hooksDisabled=true") {
			t.Fatalf("disabled install error = %v", err)
		}
		status := Status(AgentFactory, path)
		if status.Installed || !strings.Contains(status.Message, "present but inactive") {
			t.Fatalf("disabled status = %+v", status)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != config {
			t.Fatalf("rejected install changed config:\n%s", data)
		}
	})

	t.Run("settings flag disables root migration", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), ".factory")
		root := filepath.Join(dir, "hooks.json")
		settings := filepath.Join(dir, "settings.json")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		const config = `{"hooks":{"hooksDisabled":true,"showHookOutput":true}}`
		if err := os.WriteFile(settings, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(AgentFactory, root, auspexBinary, "", false); err == nil || !strings.Contains(err.Error(), settings) {
			t.Fatalf("disabled fallback install error = %v, want %s", err, settings)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("disabled install created root: %v", err)
		}
	})

	t.Run("standalone false overrides settings true", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), ".factory")
		root := filepath.Join(dir, "hooks.json")
		settings := filepath.Join(dir, "settings.json")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root, []byte(`{"hooksDisabled":false,"showHookOutput":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settings, []byte(`{"hooks":{"hooksDisabled":true,"showHookOutput":false}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(AgentFactory, root, auspexBinary, "", false); err != nil {
			t.Fatalf("explicit enabled override should install: %v", err)
		}
		status := Status(AgentFactory, root)
		if !status.Installed {
			t.Fatalf("enabled override status = %+v", status)
		}
		data, err := os.ReadFile(root)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"hooksDisabled": false`) || !strings.Contains(string(data), `"showHookOutput": true`) {
			t.Fatalf("root flags were not preserved:\n%s", data)
		}
	})
}

func TestFactoryStrictSchemaValidationAndFractionalTimeout(t *testing.T) {
	invalid := map[string]string{
		"empty file":          ``,
		"null event":          `{"PreToolUse":null}`,
		"missing group hooks": `{"PreToolUse":[{}]}`,
		"missing ref type":    `{"PreToolUse":[{"hooks":[{"command":"echo"}]}]}`,
		"wrong ref type":      `{"PreToolUse":[{"hooks":[{"type":"shell","command":"echo"}]}]}`,
		"missing command":     `{"PreToolUse":[{"hooks":[{"type":"command"}]}]}`,
		"string timeout":      `{"PreToolUse":[{"hooks":[{"type":"command","command":"echo","timeout":"1"}]}]}`,
		"nonboolean flag":     `{"hooksDisabled":"false"}`,
	}
	for name, config := range invalid {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Install(AgentFactory, path, auspexBinary, "", false); err == nil {
				t.Fatal("Install should reject vendor-invalid hook schema")
			}
			if _, err := StatusErr(AgentFactory, path); err == nil {
				t.Fatal("StatusErr should reject vendor-invalid hook schema")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != config {
				t.Fatalf("rejected schema changed bytes: %s", data)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "hooks.json")
	const valid = `{"PostToolUse":[{"matcher":"","commandRegex":".*","hooks":[{"type":"command","command":"echo foreign","timeout":0.5}]}],"showHookOutput":true}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentFactory, path, auspexBinary, "", false); err != nil {
		t.Fatalf("valid fractional timeout rejected: %v", err)
	}
	if _, err := Uninstall(AgentFactory, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"timeout": 0.5`, `"commandRegex": ".*"`, `"showHookOutput": true`, "echo foreign"} {
		if !strings.Contains(text, want) {
			t.Errorf("round trip lost %s:\n%s", want, data)
		}
	}
}

func TestFactoryMigrationDoesNotAliasMarkerFirstSourceGroups(t *testing.T) {
	for _, source := range []string{"legacy standalone", "settings fallback"} {
		t.Run(source, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), ".factory")
			canonical := filepath.Join(dir, "hooks.json")
			legacy := filepath.Join(dir, "hooks", "hooks.json")
			settings := filepath.Join(dir, "settings.json")
			if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
				t.Fatal(err)
			}

			sourcePath := legacy
			config := `{"PostToolUse":[{"hooks":[{"type":"command","command":"old --installed-by=auspex"},{"type":"command","command":"echo marker-first-foreign"}]}]}`
			if source == "settings fallback" {
				sourcePath = settings
				config = `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"old --installed-by=auspex"},{"type":"command","command":"echo marker-first-foreign"}]}]}}`
			}
			if err := os.WriteFile(sourcePath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := Install(AgentFactory, canonical, auspexBinary, "", false); err != nil {
				t.Fatal(err)
			}
			canonicalData, err := os.ReadFile(canonical)
			if err != nil {
				t.Fatal(err)
			}
			canonicalText := hookCommandText(string(canonicalData))
			if !strings.Contains(canonicalText, "marker-first-foreign") || strings.Contains(canonicalText, "old --installed-by=auspex") {
				t.Fatalf("canonical migration did not preserve only the foreign hook:\n%s", canonicalData)
			}

			sourceData, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			sourceText := hookCommandText(string(sourceData))
			if !strings.Contains(sourceText, "marker-first-foreign") || strings.Contains(sourceText, auspexHookMarker) {
				t.Fatalf("source cleanup retained a stale marker or lost the foreign hook:\n%s", sourceData)
			}
		})
	}
}

func TestFactoryInstallMigratesLegacyStandaloneWithoutLosingContent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	settings := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	const legacyConfig = `{
  "x-factory-future": {"preserve": true},
  "PostToolUse": [{"hooks":[{"type":"command","command":"echo legacy-foreign"},{"type":"command","command":"old --installed-by=auspex"}]}],
  "Notification": [{"hooks":[{"type":"command","command":"echo notification-foreign"}]}]
}`
	const settingsConfig = `{
  "model": "preserve-settings",
  "hooks": {
    "UserPromptSubmit": [{"hooks":[{"type":"command","command":"echo settings-foreign"},{"type":"command","command":"old-settings --installed-by=auspex"}]}]
  }
}`
	if err := os.WriteFile(legacy, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(settingsConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		legacy + backupSuffix:   "legacy pristine backup",
		settings + backupSuffix: "settings pristine backup",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := Install(AgentFactory, canonical, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !strings.Contains(rep.Message, "migrated legacy hooks/hooks.json") {
		t.Fatalf("install report = %+v, want migration note", rep)
	}

	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalText := hookCommandText(string(canonicalData))
	for _, foreign := range []string{"legacy-foreign", "notification-foreign", "settings-foreign", "x-factory-future"} {
		if !strings.Contains(canonicalText, foreign) {
			t.Errorf("canonical migration lost %q:\n%s", foreign, canonicalData)
		}
	}
	if strings.Contains(canonicalText, "old-settings") || strings.Contains(canonicalText, `"command": "old `) {
		t.Errorf("canonical migration retained stale auspex command:\n%s", canonicalData)
	}
	if got := strings.Count(canonicalText, auspexHookMarker); got != len(factoryHookEvents) {
		t.Errorf("canonical auspex markers = %d, want %d:\n%s", got, len(factoryHookEvents), canonicalData)
	}

	for _, check := range []struct {
		path     string
		foreigns []string
	}{
		{legacy, []string{"legacy-foreign", "notification-foreign", "x-factory-future"}},
		{settings, []string{"settings-foreign", "preserve-settings"}},
	} {
		data, readErr := os.ReadFile(check.path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		text := hookCommandText(string(data))
		if strings.Contains(text, auspexHookMarker) {
			t.Errorf("stale auspex marker survived in %s:\n%s", check.path, data)
		}
		for _, foreign := range check.foreigns {
			if !strings.Contains(text, foreign) {
				t.Errorf("cleanup lost %q from %s:\n%s", foreign, check.path, data)
			}
		}
	}
	for path, want := range map[string]string{
		legacy + backupSuffix:   "legacy pristine backup",
		settings + backupSuffix: "settings pristine backup",
	} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read backup %s: %v", path, readErr)
		} else if string(data) != want {
			t.Errorf("backup %s = %q, want %q", path, data, want)
		}
	}
}

func TestFactoryInstallDoesNotMergeShadowedLegacyStandalone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonical, []byte(`{"PreToolUse":[{"hooks":[{"type":"command","command":"echo root-foreign"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"PostToolUse":[{"hooks":[{"type":"command","command":"echo shadowed-foreign"},{"type":"command","command":"old --installed-by=auspex"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(AgentFactory, canonical, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonicalData), "shadowed-foreign") {
		t.Fatalf("inactive legacy foreign hook was incorrectly merged:\n%s", canonicalData)
	}
	legacyData, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyText := hookCommandText(string(legacyData))
	if !strings.Contains(legacyText, "shadowed-foreign") || strings.Contains(legacyText, auspexHookMarker) {
		t.Fatalf("legacy cleanup did not preserve only foreign content:\n%s", legacyData)
	}
}

// A hooks.json event overrides the same settings.json event. Installation must
// carry the soon-to-be-shadowed foreign groups forward while removing old
// auspex-owned fallback entries.
func TestFactoryInstallCarriesForwardLegacyFallbackHooks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "settings.json")
	const legacyConfig = `{
  "model": "keep-me",
  "hooks": {
    "PostToolUse": [{"matcher":"Edit","hooks":[{"type":"command","command":"echo foreign"}]}],
    "Notification": [{"hooks":[{"type":"command","command":"old-watch --installed-by=auspex"}]}]
  }
}`
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	const pristineBackup = "pre-existing pristine backup"
	if err := os.WriteFile(legacy+backupSuffix, []byte(pristineBackup), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := Install(AgentFactory, canonical, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep.BackupPath != legacy+backupSuffix {
		t.Errorf("backup path = %q, want legacy backup %q", rep.BackupPath, legacy+backupSuffix)
	}

	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalText := hookCommandText(string(canonicalData))
	if !strings.Contains(canonicalText, "echo foreign") {
		t.Fatalf("canonical file shadowed legacy foreign hook:\n%s", canonicalData)
	}
	if strings.Contains(canonicalText, "old-watch") {
		t.Fatalf("stale auspex fallback hook was copied into canonical file:\n%s", canonicalData)
	}
	if got := strings.Count(canonicalText, auspexHookMarker); got != len(factoryHookEvents) {
		t.Fatalf("canonical auspex markers = %d, want %d:\n%s", got, len(factoryHookEvents), canonicalData)
	}

	legacyData, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyText := hookCommandText(string(legacyData))
	if !strings.Contains(legacyText, "echo foreign") || !strings.Contains(legacyText, "keep-me") {
		t.Fatalf("legacy foreign config was not preserved:\n%s", legacyData)
	}
	if strings.Contains(legacyText, auspexHookMarker) {
		t.Fatalf("stale auspex entry survived in legacy fallback:\n%s", legacyData)
	}
	backupData, err := os.ReadFile(legacy + backupSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if string(backupData) != pristineBackup {
		t.Errorf("existing legacy backup was overwritten: %q", backupData)
	}
}

// Existing canonical events already shadow the same fallback event, but a
// fallback-only event remains active. Adding auspex to that event must carry its
// foreign group forward before the new canonical key shadows it.
func TestFactoryInstallCarriesForwardNewlyShadowedFallbackEvent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const canonicalConfig = `{"PreToolUse":[{"hooks":[{"type":"command","command":"echo canonical-foreign"}]}]}`
	const legacyConfig = `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"echo legacy-foreign"},{"type":"command","command":"old-watch --installed-by=auspex"}]}]}}`
	if err := os.WriteFile(canonical, []byte(canonicalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(AgentFactory, canonical, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalText := hookCommandText(string(canonicalData))
	if !strings.Contains(canonicalText, "canonical-foreign") {
		t.Fatalf("canonical foreign hook was lost:\n%s", canonicalData)
	}
	if !strings.Contains(canonicalText, "legacy-foreign") {
		t.Fatalf("active fallback hook was shadowed instead of carried forward:\n%s", canonicalData)
	}
	legacyData, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyText := hookCommandText(string(legacyData))
	if !strings.Contains(legacyText, "legacy-foreign") || strings.Contains(legacyText, auspexHookMarker) {
		t.Fatalf("legacy cleanup did not preserve only the foreign hook:\n%s", legacyData)
	}
}

func TestFactoryUninstallCleansCanonicalAndLegacyFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacyStandalone := filepath.Join(dir, "hooks", "hooks.json")
	settings := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(filepath.Dir(legacyStandalone), 0o700); err != nil {
		t.Fatal(err)
	}
	const canonicalConfig = `{"PreToolUse":[{"hooks":[{"type":"command","command":"echo canonical-foreign"},{"type":"command","command":"watch --installed-by=auspex"}]}]}`
	const standaloneConfig = `{"Notification":[{"hooks":[{"type":"command","command":"echo standalone-foreign"},{"type":"command","command":"standalone-watch --installed-by=auspex"}]}]}`
	const settingsConfig = `{"model":"keep","hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"echo settings-foreign"},{"type":"command","command":"old-watch --installed-by=auspex"}]}]}}`
	if err := os.WriteFile(canonical, []byte(canonicalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyStandalone, []byte(standaloneConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(settingsConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonical+backupSuffix, []byte("canonical backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyStandalone+backupSuffix, []byte("standalone backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings+backupSuffix, []byte("settings backup"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := Uninstall(AgentFactory, canonical)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Fatal("uninstall should remove canonical and legacy auspex hooks")
	}
	for _, check := range []struct {
		path    string
		foreign string
	}{
		{canonical, "canonical-foreign"},
		{legacyStandalone, "standalone-foreign"},
		{settings, "settings-foreign"},
	} {
		data, readErr := os.ReadFile(check.path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		text := hookCommandText(string(data))
		if !strings.Contains(text, check.foreign) {
			t.Errorf("foreign hook missing from %s:\n%s", check.path, data)
		}
		if strings.Contains(text, auspexHookMarker) {
			t.Errorf("auspex hook survived in %s:\n%s", check.path, data)
		}
	}
	for path, want := range map[string]string{
		canonical + backupSuffix:        "canonical backup",
		legacyStandalone + backupSuffix: "standalone backup",
		settings + backupSuffix:         "settings backup",
	} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(data) != want {
			t.Errorf("backup %s = %q, want %q", path, data, want)
		}
	}
}

func TestFactoryStatusAndUninstallActiveLegacyFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const legacyConfig = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign"},{"type":"command","command":"watch --installed-by=auspex"}]}]}}`
	if err := os.WriteFile(legacy, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	status := Status(AgentFactory, canonical)
	if !status.Installed || status.SettingsPath != legacy || !strings.Contains(status.Message, "settings.json") {
		t.Fatalf("legacy fallback status = %+v, want installed at %s", status, legacy)
	}
	rep, err := Uninstall(AgentFactory, canonical)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Fatal("uninstall should clean active legacy fallback")
	}
	data, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	text := hookCommandText(string(data))
	if !strings.Contains(text, "echo foreign") || strings.Contains(text, auspexHookMarker) {
		t.Fatalf("legacy uninstall did not preserve only foreign hook:\n%s", data)
	}
	if status := Status(AgentFactory, canonical); status.Installed {
		t.Fatalf("post-uninstall status = %+v, want not installed", status)
	}
}

func TestFactoryStatusAndUninstallActiveLegacyStandalone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	const config = `{"PostToolUse":[{"hooks":[{"type":"command","command":"echo foreign"},{"type":"command","command":"watch --installed-by=auspex"}]}]}`
	if err := os.WriteFile(legacy, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	status := Status(AgentFactory, canonical)
	if !status.Installed || status.SettingsPath != legacy || !strings.Contains(status.Message, "legacy hooks/hooks.json") {
		t.Fatalf("legacy standalone status = %+v, want active at %s", status, legacy)
	}
	rep, err := Uninstall(AgentFactory, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Changed {
		t.Fatal("uninstall should clean selected legacy standalone")
	}
	data, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	text := hookCommandText(string(data))
	if !strings.Contains(text, "echo foreign") || strings.Contains(text, auspexHookMarker) {
		t.Fatalf("legacy standalone cleanup did not preserve only foreign content:\n%s", data)
	}
}

func TestFactoryStatusDoesNotCountDormantLegacyFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonical, []byte(`{"PreToolUse":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"watch --installed-by=auspex"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	status := Status(AgentFactory, canonical)
	if status.Installed {
		t.Fatalf("dormant fallback must not be reported active: %+v", status)
	}
	if status.SettingsPath != canonical || !strings.Contains(status.Message, "shadowed") {
		t.Fatalf("dormant fallback status = %+v", status)
	}
}

func TestFactoryInstallPreflightsMalformedLegacyFallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"hooks":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentFactory, canonical, auspexBinary, "", false); err == nil {
		t.Fatal("Install should reject malformed active fallback before creating hooks.json")
	}
	if _, err := os.Stat(canonical); !os.IsNotExist(err) {
		t.Fatalf("canonical file should not exist after failed preflight: %v", err)
	}
	if _, err := StatusErr(AgentFactory, canonical); err == nil {
		t.Fatal("StatusErr should reject malformed active legacy fallback")
	}
}

func TestFactoryMalformedActiveLegacyStandaloneBlocksRootMigration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"PostToolUse":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentFactory, canonical, auspexBinary, "", false); err == nil {
		t.Fatal("Install should reject malformed selected hooks/hooks.json")
	}
	if _, err := os.Stat(canonical); !os.IsNotExist(err) {
		t.Fatalf("canonical file should not exist after failed migration: %v", err)
	}
	if _, err := StatusErr(AgentFactory, canonical); err == nil {
		t.Fatal("StatusErr should reject malformed selected hooks/hooks.json")
	}
}

func TestFactoryMalformedShadowedLegacyStandaloneDoesNotBlockRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "hooks", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonical, []byte(`{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := []byte(`{"PostToolUse":`)
	if err := os.WriteFile(legacy, malformed, 0o600); err != nil {
		t.Fatal(err)
	}

	install, err := Install(AgentFactory, canonical, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install should ignore malformed shadowed standalone: %v", err)
	}
	if !strings.Contains(install.Message, "could not be inspected") {
		t.Fatalf("install report = %+v, want shadowed-source warning", install)
	}
	if _, err := StatusErr(AgentFactory, canonical); err != nil {
		t.Fatalf("StatusErr should validate selected root only: %v", err)
	}
	uninstall, err := Uninstall(AgentFactory, canonical)
	if err != nil {
		t.Fatalf("Uninstall should ignore malformed shadowed standalone: %v", err)
	}
	if !strings.Contains(uninstall.Message, "could not be inspected") {
		t.Fatalf("uninstall report = %+v, want shadowed-source warning", uninstall)
	}
	after, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(malformed) {
		t.Fatalf("shadowed malformed bytes changed: %q", after)
	}
}

// A malformed settings.json is irrelevant while a valid hooks.json exists.
// Reinstall and uninstall should operate on the active file, leave the dormant
// bytes untouched, and report that cleanup could not inspect the fallback.
func TestFactoryMalformedDormantFallbackDoesNotBlockCanonicalActions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonical := filepath.Join(dir, "hooks.json")
	legacy := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonical, []byte(`{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := []byte(`{"hooks":`)
	if err := os.WriteFile(legacy, malformed, 0o600); err != nil {
		t.Fatal(err)
	}

	install, err := Install(AgentFactory, canonical, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("canonical Install should ignore malformed dormant fallback: %v", err)
	}
	if !install.Installed || !strings.Contains(install.Message, "could not be inspected") {
		t.Fatalf("install report = %+v, want installed with fallback warning", install)
	}
	if _, err := StatusErr(AgentFactory, canonical); err != nil {
		t.Fatalf("StatusErr should validate the active canonical file only: %v", err)
	}
	legacyData, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(legacyData) != string(malformed) {
		t.Fatalf("install rewrote malformed dormant fallback: %q", legacyData)
	}

	uninstall, err := Uninstall(AgentFactory, canonical)
	if err != nil {
		t.Fatalf("canonical Uninstall should ignore malformed dormant fallback: %v", err)
	}
	if !uninstall.Changed || !strings.Contains(uninstall.Message, "could not be inspected") {
		t.Fatalf("uninstall report = %+v, want changed with fallback warning", uninstall)
	}
	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalText := hookCommandText(string(canonicalData))
	if !strings.Contains(canonicalText, "echo foreign") || strings.Contains(canonicalText, auspexHookMarker) {
		t.Fatalf("canonical uninstall did not preserve only foreign hook:\n%s", canonicalData)
	}
	legacyData, err = os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(legacyData) != string(malformed) {
		t.Fatalf("uninstall rewrote malformed dormant fallback: %q", legacyData)
	}
}

// Failure injection at the final write verifies the safety invariant: both
// lower-precedence sources are cleaned first, and a failed canonical write
// leaves auspex active in hooks.json rather than dormant in either fallback.
func TestFactoryUninstallPartialFailureLeavesSafeState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".factory")
	canonicalPath := filepath.Join(dir, "hooks.json")
	standalonePath := filepath.Join(dir, "hooks", "hooks.json")
	settingsPath := filepath.Join(dir, "settings.json")
	if err := os.MkdirAll(filepath.Dir(standalonePath), 0o700); err != nil {
		t.Fatal(err)
	}
	const canonicalConfig = `{"PreToolUse":[{"hooks":[{"type":"command","command":"canonical --installed-by=auspex"}]}]}`
	const standaloneConfig = `{"Notification":[{"hooks":[{"type":"command","command":"echo standalone-foreign"},{"type":"command","command":"standalone --installed-by=auspex"}]}]}`
	const settingsConfig = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo settings-foreign"},{"type":"command","command":"settings --installed-by=auspex"}]}]}}`
	if err := os.WriteFile(canonicalPath, []byte(canonicalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(standalonePath, []byte(standaloneConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(settingsConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical, err := readFactoryHooksFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := readFactoryHooksFile(standalonePath)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := readSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !canonical.removeAuspexHooks() || !standalone.removeAuspexHooks() || !settings.removeAuspexHooks() {
		t.Fatal("fixture must contain auspex hooks in all files")
	}

	injected := errors.New("injected canonical write failure")
	var writes []string
	err = writeFactoryUninstallChanges(
		true,
		true,
		func() error {
			writes = append(writes, settingsPath)
			return writeSettings(settingsPath, settings)
		},
		true,
		func() error {
			writes = append(writes, standalonePath)
			return writeFactoryHooksFile(standalonePath, standalone)
		},
		true,
		func() error {
			writes = append(writes, canonicalPath)
			return injected
		},
	)
	if !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected failure", err)
	}
	if len(writes) != 3 || writes[0] != standalonePath || writes[1] != settingsPath || writes[2] != canonicalPath {
		t.Fatalf("write order = %v, want dormant legacy standalone, settings, canonical", writes)
	}
	for _, check := range []struct {
		path    string
		foreign string
	}{{settingsPath, "settings-foreign"}, {standalonePath, "standalone-foreign"}} {
		data, readErr := os.ReadFile(check.path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		text := hookCommandText(string(data))
		if !strings.Contains(text, check.foreign) || strings.Contains(text, auspexHookMarker) {
			t.Fatalf("fallback %s was not safely cleaned first:\n%s", check.path, data)
		}
	}
	canonicalData, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hookCommandText(string(canonicalData)), auspexHookMarker) {
		t.Fatalf("failed canonical write should leave active auspex hook intact:\n%s", canonicalData)
	}
}

func TestFactoryUninstallWriteOrderWithoutRoot(t *testing.T) {
	var writes []string
	err := writeFactoryUninstallChanges(
		false,
		true,
		func() error {
			writes = append(writes, "settings")
			return nil
		},
		true,
		func() error {
			writes = append(writes, "legacy")
			return nil
		},
		false,
		func() error {
			writes = append(writes, "root")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(writes, ","); got != "settings,legacy" {
		t.Fatalf("write order without root = %s, want settings,legacy", got)
	}
}
