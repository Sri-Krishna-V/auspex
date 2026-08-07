package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readAntigravityTop(t *testing.T, path string) map[string]json.RawMessage {
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

func readAntigravityDefinition(t *testing.T, path string) antigravityDefinition {
	t.Helper()
	var definition antigravityDefinition
	if err := json.Unmarshal(readAntigravityTop(t, path)[antigravityHookKey], &definition); err != nil {
		t.Fatalf("parse auspex definition: %v", err)
	}
	return definition
}

func TestAntigravityInstallWritesDocumentedShapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gemini", "config", "hooks.json")
	rep, err := Install(AgentAntigravity, path, auspexBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v", rep)
	}

	definition := readAntigravityDefinition(t, path)
	for name, groups := range map[string][]hookGroup{
		"PreToolUse":  definition.PreToolUse,
		"PostToolUse": definition.PostToolUse,
	} {
		if len(groups) != 1 || groups[0].Matcher != "*" || len(groups[0].Hooks) != 1 {
			t.Fatalf("%s groups = %+v", name, groups)
		}
		if !strings.Contains(hookCommandText(groups[0].Hooks[0].Command), auspexHookMarker) {
			t.Errorf("%s command missing marker", name)
		}
	}
	if len(definition.Stop) != 1 {
		t.Fatalf("Stop handlers = %+v", definition.Stop)
	}
	if !strings.Contains(hookCommandText(definition.Stop[0].Command), "--agent antigravity") {
		t.Errorf("Stop command = %q", definition.Stop[0].Command)
	}
	if strings.Contains(hookCommandText(definition.Stop[0].Command), "--enforce") {
		t.Errorf("observe-only command contains --enforce: %q", definition.Stop[0].Command)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(readAntigravityTop(t, path)[antigravityHookKey], &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3 {
		t.Fatalf("event keys = %v, want PreToolUse, PostToolUse, Stop", raw)
	}
	if _, ok := raw["PreInvocation"]; ok {
		t.Error("PreInvocation must not be mislabeled as a user prompt")
	}
	if strings.Contains(string(raw["Stop"]), `"hooks"`) {
		t.Errorf("Stop must be a direct handler list: %s", raw["Stop"])
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); !modeMatches(got, 0o600) {
		t.Errorf("mode = %o, want 600", got)
	}
}

func TestAntigravityInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentAntigravity, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentAntigravity, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("reinstall changed output:\n%s\n---\n%s", first, second)
	}
}

func TestAntigravityInstallWiresRuntimeArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const out = "/home/u/.auspex/events.ndjson"
	if _, err := Install(AgentAntigravity, path, auspexBinary, out, false); err != nil {
		t.Fatal(err)
	}
	cmd := readAntigravityDefinition(t, path).PreToolUse[0].Hooks[0].Command
	if command := hookCommandText(cmd); !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
		t.Errorf("command missing output args: %q", cmd)
	}
}

func TestAntigravityPreservesForeignDefinitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const seeded = `{"other":{"PreToolUse":[{"matcher":"run_command","hooks":[{"command":"echo hi"}]}]}}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentAntigravity, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	if raw := readAntigravityTop(t, path)["other"]; !strings.Contains(string(raw), "echo hi") {
		t.Errorf("foreign definition changed: %s", raw)
	}
	if _, err := Uninstall(AgentAntigravity, path); err != nil {
		t.Fatal(err)
	}
	top := readAntigravityTop(t, path)
	if _, ok := top[antigravityHookKey]; ok {
		t.Error("auspex definition remains after uninstall")
	}
	if !strings.Contains(string(top["other"]), "echo hi") {
		t.Errorf("foreign definition changed: %s", top["other"])
	}
}

func TestAntigravityRefusesForeignAuspexDefinition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const seeded = `{"auspex":{"Stop":[{"command":"echo user-owned"}]}}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentAntigravity, path, auspexBinary, "", false); err == nil {
		t.Fatal("Install succeeded over a non-auspex definition")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != seeded {
		t.Errorf("foreign definition changed: %s", got)
	}
}

func TestAntigravityUninstallRemovesOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentAntigravity, path, "/opt/tools/agent-watch", "", false); err != nil {
		t.Fatal(err)
	}
	if !Status(AgentAntigravity, path).Installed {
		t.Fatal("status did not recognize marker-bearing commands")
	}
	if _, err := Uninstall(AgentAntigravity, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("owned file remains after uninstall: %v", err)
	}
}

func TestAntigravityBackupPreservesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const original = `{"other":{"Stop":[{"command":"keep me"}]}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentAntigravity, path, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("backup = %s", got)
	}
}

func TestAntigravityHooksPathUsesDocumentedHome(t *testing.T) {
	t.Setenv("GEMINI_CLI_HOME", t.TempDir())
	got := AntigravityHooksPath("/home/u")
	want := filepath.Join("/home/u", ".gemini", "config", "hooks.json")
	if got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestAntigravityEnforceInstallWiresOnlyPreToolUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentAntigravity, path, auspexBinary, "", true); err != nil {
		t.Fatal(err)
	}
	definition := readAntigravityDefinition(t, path)
	if command := definition.PreToolUse[0].Hooks[0].Command; !strings.Contains(hookCommandText(command), "--enforce") {
		t.Errorf("PreToolUse command lacks --enforce: %q", command)
	}
	for name, command := range map[string]string{
		"PostToolUse": definition.PostToolUse[0].Hooks[0].Command,
		"Stop":        definition.Stop[0].Command,
	} {
		if strings.Contains(hookCommandText(command), "--enforce") {
			t.Errorf("%s command contains --enforce: %q", name, command)
		}
	}
}
