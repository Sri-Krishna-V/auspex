package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSStringEscapesAllJavaScriptControlCharacters(t *testing.T) {
	want := "binary\x00\x1f\n\"\\\u2028\u2029"
	got := jsString(want)
	if strings.ContainsRune(got, '\x00') || strings.ContainsRune(got, '\x1f') ||
		strings.ContainsRune(got, '\u2028') || strings.ContainsRune(got, '\u2029') {
		t.Fatalf("jsString left a source-breaking character unescaped: %q", got)
	}
	var roundTrip string
	if err := json.Unmarshal([]byte(got), &roundTrip); err != nil {
		t.Fatalf("jsString output is not a JSON/JavaScript string literal: %v", err)
	}
	if roundTrip != want {
		t.Fatalf("jsString round trip = %q, want %q", roundTrip, want)
	}
}

// OpenCode uses a generated TypeScript plugin rather than a JSON settings merge.
func TestOpenCodeInstallWritesObserveOnlyPlugin(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".config", "opencode", "plugins", "auspex.ts")
	rep, err := Install(AgentOpenCode, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, openCodePluginMarker) {
		t.Errorf("plugin missing auspex marker: %s", src)
	}
	// The absolute binary path is baked in (not a PATH lookup) so the plugin fires
	// the exact binary the installer resolved.
	if !strings.Contains(src, auspexBinary) {
		t.Errorf("plugin must bake in the absolute binary path %q", auspexBinary)
	}
	// Each forwarded lifecycle arg the installer wires must appear in the source.
	for _, lc := range OpenCodeLifecycleArgs() {
		if !strings.Contains(src, lc) {
			t.Errorf("plugin missing lifecycle arg %q", lc)
		}
	}
	if !strings.Contains(src, "--agent") || !strings.Contains(src, "opencode") {
		t.Errorf("plugin must invoke auspex with --agent opencode")
	}
	// Plugin failures must not interrupt OpenCode or imply enforcement.
	if !strings.Contains(src, "try") || !strings.Contains(src, "catch") {
		t.Errorf("plugin must wrap forwarding in try/catch (never-throw guard)")
	}
	if strings.Contains(src, "--enforce") {
		t.Errorf("observe-only plugin must not carry --enforce: %s", src)
	}
	// detached + unref so a slow/missing binary can never keep the agent alive or
	// block the tool.
	if !strings.Contains(src, "detached") || !strings.Contains(src, "unref") {
		t.Errorf("plugin must spawn detached + unref (fire-and-forget)")
	}
	for _, want := range []string{"SESSION_CONTEXT", "MAX_CONTEXTS", `"chat.message"`, `"chat.params"`, `"message.updated"`, `forward("prompt-submit"`, `forward("assistant"`, "modelProvider", "subAgent", "info.directory", "new Date().toISOString()"} {
		if !strings.Contains(src, want) {
			t.Errorf("plugin missing session context field %q", want)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("plugin perms = %o, want 600", perm)
	}
}

// TestOpenCodeInstallWiresExactlyTheIngestedLifecycles pins that the installer
// wires exactly the lifecycles the generated plugin emits.
func TestOpenCodeInstallWiresExactlyTheIngestedLifecycles(t *testing.T) {
	want := map[Lifecycle]bool{
		LifecycleOpenCodePreTool:  true,
		LifecycleOpenCodePostTool: true,
		LifecyclePromptSubmit:     true,
		LifecycleAssistant:        true,
		LifecycleSessionStart:     true,
		LifecycleSessionEnd:       true,
	}
	if len(openCodeHookLifecycles) != len(want) {
		t.Fatalf("openCodeHookLifecycles has %d entries, want %d", len(openCodeHookLifecycles), len(want))
	}
	for _, lc := range openCodeHookLifecycles {
		if !want[lc] {
			t.Errorf("unexpected wired OpenCode lifecycle %q", lc)
		}
	}
}

// TestOpenCodeInstallIsIdempotent: a second install rewrites the same stable file
// with byte-identical content and reports installed.
func TestOpenCodeInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auspex.ts")
	if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("re-install produced different content:\n%s\n---\n%s", first, second)
	}
	if rep := Status(AgentOpenCode, path); !rep.Installed {
		t.Error("status after re-install should be installed")
	}
}

// TestOpenCodeInstallWiresDurableOutputFile: when an output file is supplied, the
// generated plugin threads --output=file and the path so a hook-detected finding
// is not lost.
func TestOpenCodeInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auspex.ts")
	const out = "/home/u/.auspex/findings.ndjson"
	if _, err := Install(AgentOpenCode, path, auspexBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, "--output=file") || !strings.Contains(src, out) {
		t.Errorf("plugin missing durable output wiring: %s", src)
	}
}

// TestOpenCodeInstallDetectionIsRenameProof: detection keys on the in-file marker,
// not the binary path, so a binary with no "auspex" in its name still installs,
// reports installed, uninstalls, and reinstalls without duplication.
func TestOpenCodeInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "auspex") {
		t.Fatalf("test binary path %q must not contain auspex", renamed)
	}
	path := filepath.Join(t.TempDir(), "auspex.ts")
	if _, err := Install(AgentOpenCode, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentOpenCode, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if _, err := Install(AgentOpenCode, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	rep, err := Uninstall(AgentOpenCode, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if rep := Status(AgentOpenCode, path); rep.Installed {
		t.Error("status after uninstall should be not-installed")
	}
}

// TestOpenCodeBackupPreservesPristineOriginal: a pre-existing auspex-owned plugin
// is backed up once with its original content before being overwritten, across
// repeated install and install→uninstall→install cycles.
func TestOpenCodeBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = openCodePluginMarker + "\n// old auspex plugin body — keep me\n"
	check := func(t *testing.T, mutate func(path string)) {
		path := filepath.Join(t.TempDir(), "auspex.ts")
		if err := os.WriteFile(path, []byte(pristine), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		mutate(path)
		data, err := os.ReadFile(path + backupSuffix)
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if !strings.Contains(string(data), "keep me") {
			t.Fatalf("backup is not the pristine original: %s", data)
		}
	}
	t.Run("install twice", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentOpenCode, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// TestOpenCodeUninstallRemovesOnlyAuspexFile: uninstall removes auspex's own
// plugin but leaves any other plugin/file in the directory untouched.
func TestOpenCodeUninstallRemovesOnlyAuspexFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	auspexPath := filepath.Join(dir, "auspex.ts")
	otherPath := filepath.Join(dir, "user-plugin.ts")
	const otherBody = "// a user's own plugin\nexport default async () => ({});\n"
	if err := os.WriteFile(otherPath, []byte(otherBody), 0o600); err != nil {
		t.Fatalf("seed other: %v", err)
	}
	if _, err := Install(AgentOpenCode, auspexPath, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentOpenCode, auspexPath)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if _, err := os.Stat(auspexPath); !os.IsNotExist(err) {
		t.Errorf("auspex plugin should be removed, stat err = %v", err)
	}
	data, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatalf("unrelated plugin should survive: %v", err)
	}
	if string(data) != otherBody {
		t.Errorf("unrelated plugin was modified: %s", data)
	}
}

// TestOpenCodeInstallRefusesToOverwriteForeignFile: a pre-existing file at the
// install path that is NOT auspex-owned (e.g. a user's own auspex.ts plugin) must
// be left untouched — install refuses with an error rather than backing up and
// clobbering it, the same installer-safety contract uninstall already honors.
func TestOpenCodeInstallRefusesToOverwriteForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auspex.ts")
	const foreign = "// a user's own plugin, NOT auspex's\nexport default async () => ({});\n"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Install(AgentOpenCode, path, auspexBinary, "", false)
	if err == nil {
		t.Fatal("Install over a foreign file should be refused, got nil error")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("foreign file should survive: %v", err)
	}
	if string(data) != foreign {
		t.Errorf("foreign file was modified: %s", data)
	}
	// No backup of the foreign file should have been taken either (we refused before
	// touching it).
	if _, statErr := os.Stat(path + backupSuffix); !os.IsNotExist(statErr) {
		t.Errorf("refused install must not back up the foreign file, stat err = %v", statErr)
	}
}

// TestOpenCodeUninstallNonAuspexFileIsNoOp: a file at auspex's path that is NOT
// auspex-owned is left untouched (uninstall removes only what auspex installed).
func TestOpenCodeUninstallNonAuspexFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auspex.ts")
	const foreign = "// not auspex's\nexport default async () => ({});\n"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rep, err := Uninstall(AgentOpenCode, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall of a non-auspex file must not report a change")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("foreign file should survive: %v", err)
	}
	if string(data) != foreign {
		t.Errorf("foreign file was modified: %s", data)
	}
}

// TestOpenCodeUninstallNoFileIsNoOp: uninstalling when no plugin file exists is a
// clean no-op.
func TestOpenCodeUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.ts")
	rep, err := Uninstall(AgentOpenCode, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

// TestOpenCodeStatusReflectsInstallState: status is not-installed before install,
// installed after.
func TestOpenCodeStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auspex.ts")
	if rep := Status(AgentOpenCode, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentOpenCode, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

// OpenCode can block from a plugin, but auspex intentionally supports only
// monitoring there. An enforce install is refused before writing the file.
func TestOpenCodeEnforceInstallIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".config", "opencode", "plugins", "auspex.ts")
	_, err := Install(AgentOpenCode, path, auspexBinary, "", true)
	if err == nil {
		t.Fatal("Install with --enforce for opencode should be refused, got nil error")
	}
	if !strings.Contains(err.Error(), "enforce") {
		t.Errorf("error = %q, want it to mention enforce", err.Error())
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("plugin should not exist after a refused enforce install, stat err = %v", statErr)
	}
}

// OpenCodePluginPath defaults to ~/.config/opencode/plugins/auspex.ts but honors
// XDG_CONFIG_HOME, so an install lands in the same root OpenCode itself scans.
// macOS-safe: assert on trailing path SEGMENTS (filepath.Base / Dir), never a
// full-path equality that a /var→/private/var symlink would break. The directory
// is the PLURAL "plugins/" (docs-canonical), and the file is auspex.ts.
func TestOpenCodePluginPathHonorsXDGConfigHome(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	def := OpenCodePluginPath("/home/u")
	if filepath.Base(def) != "auspex.ts" {
		t.Errorf("default path base = %q, want auspex.ts", filepath.Base(def))
	}
	if filepath.Base(filepath.Dir(def)) != "plugins" {
		t.Errorf("default path parent = %q, want plugins (plural)", filepath.Base(filepath.Dir(def)))
	}
	if filepath.Base(filepath.Dir(filepath.Dir(def))) != "opencode" {
		t.Errorf("default path grandparent = %q, want opencode", filepath.Base(filepath.Dir(filepath.Dir(def))))
	}
	// Under default (no XDG override) the opencode dir sits under ~/.config.
	if filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(def)))) != ".config" {
		t.Errorf("default path must sit under .config, got %q", def)
	}

	custom := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", custom)
	got := OpenCodePluginPath("/home/u")
	if filepath.Base(got) != "auspex.ts" {
		t.Errorf("XDG path base = %q, want auspex.ts", filepath.Base(got))
	}
	if filepath.Base(filepath.Dir(got)) != "plugins" {
		t.Errorf("XDG path parent = %q, want plugins", filepath.Base(filepath.Dir(got)))
	}
	// The opencode dir must sit directly under the XDG_CONFIG_HOME root, not under a
	// re-appended .config.
	if filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(got)))) != filepath.Base(custom) {
		t.Errorf("XDG path must sit under XDG_CONFIG_HOME root %q, got %q", custom, got)
	}
	if strings.Contains(got, ".config") {
		t.Errorf("XDG_CONFIG_HOME path must not append .config: %q", got)
	}
}

func TestOpenCodePluginPathHonorsConfigDir(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OPENCODE_CONFIG_DIR", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "ignored"))
	want := filepath.Join(root, "plugins", "auspex.ts")
	if got := OpenCodePluginPath("/unused/home"); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// An install through the XDG_CONFIG_HOME-resolved path round-trips: the file lands
// under the override root and reports installed.
func TestOpenCodeInstallUnderXDGConfigHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", root)
	path := OpenCodePluginPath("/unused/home")
	if _, err := Install(AgentOpenCode, path, auspexBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentOpenCode, path); !rep.Installed {
		t.Fatalf("status after install under XDG_CONFIG_HOME = not-installed")
	}
	if filepath.Base(path) != "auspex.ts" {
		t.Errorf("install path base = %q, want auspex.ts", filepath.Base(path))
	}
	if filepath.Base(filepath.Dir(path)) != "plugins" {
		t.Errorf("install path parent = %q, want plugins", filepath.Base(filepath.Dir(path)))
	}
}
