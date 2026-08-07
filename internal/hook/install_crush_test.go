package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrushConfigPathHonorsDirectoryOverrides(t *testing.T) {
	home := t.TempDir()
	override := filepath.Join(t.TempDir(), "global-config")
	t.Setenv("CRUSH_GLOBAL_CONFIG", override)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "ignored"))
	if got, want := CrushConfigPath(home), filepath.Join(override, "crush.json"); got != want {
		t.Fatalf("CrushConfigPath with CRUSH_GLOBAL_CONFIG = %q, want %q", got, want)
	}

	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got, want := CrushConfigPath(home), filepath.Join(xdg, "crush", "crush.json"); got != want {
		t.Fatalf("CrushConfigPath with XDG_CONFIG_HOME = %q, want %q", got, want)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	if got, want := CrushConfigPath(home), filepath.Join(home, ".config", "crush", "crush.json"); got != want {
		t.Fatalf("default CrushConfigPath = %q, want %q", got, want)
	}
}

func TestCrushInstallPreservesForeignConfigAndUninstallOwnsOnlyAuspex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crush", "crush.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{
  "theme": "dark",
  "future": {"enabled": true},
  "hooks": {
    "pre_tool_use": [
      {"name":"foreign","matcher":"^bash$","command":"foreign-hook","timeout":42,"future_field":"kept"}
    ],
    "FutureEvent": [
      {"command":"future-hook"}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := InstallWithOptions(AgentCrush, path, "/opt/auspex", InstallOptions{
		RuntimeArgs: []string{"--output=file", "--output-file", "/tmp/findings.ndjson"},
		Enforce:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || rep.BackupPath != path+backupSuffix {
		t.Fatalf("install report = %+v", rep)
	}
	if !Status(AgentCrush, path).Installed {
		t.Fatal("Crush status did not find installed hook")
	}

	cf, err := readCrushFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.hooks["pre_tool_use"]) != 1 || cf.hooks["pre_tool_use"][0].Command != "foreign-hook" {
		t.Fatalf("foreign PreToolUse hook changed: %#v", cf.hooks["pre_tool_use"])
	}
	if got := string(cf.hooks["pre_tool_use"][0].fields["future_field"]); got != `"kept"` {
		t.Fatalf("future hook field = %s, want preserved", got)
	}
	if len(cf.hooks["FutureEvent"]) != 1 || cf.hooks["FutureEvent"][0].Command != "future-hook" {
		t.Fatalf("foreign event changed: %#v", cf.hooks["FutureEvent"])
	}
	owned := cf.hooks["PreToolUse"]
	if len(owned) != 1 || !isAuspexHookCommand(owned[0].Command) || owned[0].Timeout != fastHookTimeoutSeconds {
		t.Fatalf("owned Crush hook = %#v", owned)
	}
	command := hookCommandText(owned[0].Command)
	for _, want := range []string{"--agent", "crush", "--enforce", "--output-file"} {
		if !strings.Contains(command, want) {
			t.Errorf("owned Crush command missing %q: %s", want, owned[0].Command)
		}
	}
	if owned[0].Matcher != "" {
		t.Fatalf("owned matcher = %q, want omitted match-all", owned[0].Matcher)
	}

	if _, err := InstallWithOptions(AgentCrush, path, "/opt/auspex", InstallOptions{Enforce: true}); err != nil {
		t.Fatalf("idempotent reinstall: %v", err)
	}
	cf, err = readCrushFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ownedCount := 0
	for _, refs := range cf.hooks {
		for _, ref := range refs {
			if isAuspexHookCommand(ref.Command) {
				ownedCount++
			}
		}
	}
	if ownedCount != 1 {
		t.Fatalf("reinstall left %d owned hooks, want 1", ownedCount)
	}

	if _, err := Uninstall(AgentCrush, path); err != nil {
		t.Fatal(err)
	}
	if Status(AgentCrush, path).Installed {
		t.Fatal("Crush hook remains installed")
	}
	cf, err = readCrushFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.hooks["pre_tool_use"]) != 1 || len(cf.hooks["FutureEvent"]) != 1 {
		t.Fatalf("uninstall removed foreign hooks: %#v", cf.hooks)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readTestFile(t, path)), &top); err != nil {
		t.Fatal(err)
	}
	var future struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(top["future"], &future); err != nil {
		t.Fatal(err)
	}
	if string(top["theme"]) != `"dark"` || !future.Enabled {
		t.Fatalf("uninstall changed unrelated config: %#v", top)
	}
}

func TestCrushInvalidConfigIsNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crush.json")
	if err := os.WriteFile(path, []byte(`{"hooks":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentCrush, path, "/opt/auspex", InstallOptions{}); err == nil {
		t.Fatal("install should reject a non-object hooks value")
	}
	if got := readTestFile(t, path); got != `{"hooks":[]}` {
		t.Fatalf("invalid config was overwritten: %s", got)
	}
}
