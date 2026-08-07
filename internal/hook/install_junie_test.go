package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJunieConfigPathUsesDocumentedUserLocation(t *testing.T) {
	home := t.TempDir()
	// JUNIE_HOME is deliberately not honored: Junie does not document it.
	// Additional config files use JUNIE_CONFIG_LOCATION/--config-location and
	// are targeted explicitly in auspex with --settings.
	t.Setenv("JUNIE_HOME", filepath.Join(t.TempDir(), "unsupported"))
	if got, want := JunieConfigPath(home), filepath.Join(home, ".junie", "config.json"); got != want {
		t.Fatalf("JunieConfigPath = %q, want %q", got, want)
	}
}

func TestJunieInstallPreservesConfigAndAvoidsUnsafeCallbacks(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".junie", "config.json")
	seed := settingsFile{
		values: map[string]json.RawMessage{"model": json.RawMessage(`"sonnet"`)},
		hooks: map[string][]hookGroup{
			"SessionStart":      {{Matcher: "startup", Hooks: []hookRef{{Type: "command", Command: "foreign-start"}}}},
			"PermissionRequest": {{Matcher: "Bash", Hooks: []hookRef{{Type: "command", Command: "foreign-permission"}}}},
			"StopFailure":       {{Matcher: "rate_limit", Hooks: []hookRef{{Type: "command", Command: "foreign-alert"}}}},
		},
	}
	if err := writeSettings(path, seed); err != nil {
		t.Fatal(err)
	}

	rep, err := InstallWithOptions(AgentJunie, path, "/opt/auspex", InstallOptions{Enforce: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || !Status(AgentJunie, path).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentJunie, path))
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(sf.values["model"]) != `"sonnet"` {
		t.Fatalf("unrelated Junie config changed: %s", sf.values["model"])
	}
	expectedTimeouts := map[string]int{
		"SessionStart":     fastHookTimeoutSeconds,
		"UserPromptSubmit": fastHookTimeoutSeconds,
		"PreToolUse":       fastHookTimeoutSeconds,
		"Stop":             stopHookTimeoutSeconds,
		"SessionEnd":       junieSessionEndTimeoutSeconds,
	}
	ownedCount := 0
	for event, timeout := range expectedTimeouts {
		found := 0
		for _, group := range sf.hooks[event] {
			for _, ref := range group.Hooks {
				if !isAuspexHookRef(ref) {
					continue
				}
				found++
				ownedCount++
				if ref.Type != "command" || ref.Timeout != timeout || ref.Args != nil {
					t.Errorf("%s owned hook = %#v", event, ref)
				}
				command := hookCommandText(ref.Command)
				if event == "PreToolUse" && !strings.Contains(command, "--enforce") {
					t.Errorf("PreToolUse command missing --enforce: %s", command)
				}
				if event != "PreToolUse" && strings.Contains(command, "--enforce") {
					t.Errorf("%s command unexpectedly enforces: %s", event, command)
				}
			}
		}
		if found != 1 {
			t.Errorf("%s has %d owned hooks, want 1", event, found)
		}
	}
	if ownedCount != len(junieHookEvents) {
		t.Fatalf("owned hook count = %d, want %d", ownedCount, len(junieHookEvents))
	}
	for _, event := range []string{"PermissionRequest", "StopFailure"} {
		for _, group := range sf.hooks[event] {
			for _, ref := range group.Hooks {
				if isAuspexHookRef(ref) {
					t.Fatalf("unsafe/unmappable %s callback was installed: %#v", event, ref)
				}
			}
		}
	}
	if got := sf.hooks["PermissionRequest"][0].Hooks[0].Command; got != "foreign-permission" {
		t.Fatalf("foreign PermissionRequest changed: %q", got)
	}

	if _, err := InstallWithOptions(AgentJunie, path, "/opt/auspex", InstallOptions{Enforce: true}); err != nil {
		t.Fatalf("idempotent reinstall: %v", err)
	}
	sf, err = readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	ownedCount = 0
	for _, groups := range sf.hooks {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				if isAuspexHookRef(ref) {
					ownedCount++
				}
			}
		}
	}
	if ownedCount != len(junieHookEvents) {
		t.Fatalf("reinstall left %d owned hooks, want %d", ownedCount, len(junieHookEvents))
	}
	delete(sf.hooks, "SessionEnd")
	if err := writeSettings(path, sf); err != nil {
		t.Fatal(err)
	}
	if rep := Status(AgentJunie, path); rep.Installed || !strings.Contains(rep.Message, "partial") {
		t.Fatalf("partial status = %+v", rep)
	}
	if _, err := InstallWithOptions(AgentJunie, path, "/opt/auspex", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}

	if _, err := Uninstall(AgentJunie, path); err != nil {
		t.Fatal(err)
	}
	if Status(AgentJunie, path).Installed {
		t.Fatal("Junie hooks remain installed")
	}
	sf, err = readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sf.hooks["SessionStart"][0].Hooks[0].Command; got != "foreign-start" {
		t.Fatalf("foreign SessionStart changed: %q", got)
	}
	if got := sf.hooks["StopFailure"][0].Hooks[0].Command; got != "foreign-alert" {
		t.Fatalf("foreign StopFailure changed: %q", got)
	}
}

func TestJunieInvalidConfigIsNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"hooks":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentJunie, path, "/opt/auspex", InstallOptions{}); err == nil {
		t.Fatal("install should reject a non-object hooks value")
	}
	if got := readTestFile(t, path); got != `{"hooks":[]}` {
		t.Fatalf("invalid config was overwritten: %s", got)
	}
}
