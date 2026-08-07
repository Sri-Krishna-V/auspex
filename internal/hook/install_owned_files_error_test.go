package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedSingleFileInspectionErrorsAreNotReportedAsForeign(t *testing.T) {
	for _, agent := range []string{AgentPi, AgentAmp, AgentOpenCode, AgentKiro, AgentKilo} {
		t.Run(agent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reserved-owned-file")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}

			if _, err := StatusErr(agent, path); err == nil {
				t.Fatal("StatusErr should reject a non-regular owned-file target")
			}
			rep, err := Uninstall(agent, path)
			if err == nil {
				t.Fatalf("Uninstall returned success for an uninspectable target: %+v", rep)
			}
			if rep.Changed {
				t.Fatalf("failed Uninstall reported a change: %+v", rep)
			}
			if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
				t.Fatalf("failed Uninstall changed target: info=%v err=%v", info, statErr)
			}
		})
	}
}

func TestGooseUninstallPreflightsBothOwnedFiles(t *testing.T) {
	for _, malformedPart := range []string{"manifest", "hooks"} {
		t.Run(malformedPart, func(t *testing.T) {
			root := t.TempDir()
			manifestPath := gooseManifestPath(root)
			hooksPath := gooseHooksPath(root)
			if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
				t.Fatal(err)
			}
			manifest, hooks := gooseDocuments(auspexBinary, nil, false)
			manifestData, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			hooksData, err := json.Marshal(hooks)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hooksPath, hooksData, 0o600); err != nil {
				t.Fatal(err)
			}
			malformedPath, preservedPath := manifestPath, hooksPath
			if malformedPart == "hooks" {
				malformedPath, preservedPath = hooksPath, manifestPath
			}
			if err := os.WriteFile(malformedPath, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			preservedBefore, err := os.ReadFile(preservedPath)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := StatusErr(AgentGoose, root); err == nil {
				t.Fatal("StatusErr should reject malformed Goose package content")
			}
			rep, err := Uninstall(AgentGoose, root)
			if err == nil {
				t.Fatalf("Uninstall returned success for malformed Goose content: %+v", rep)
			}
			preservedAfter, readErr := os.ReadFile(preservedPath)
			if readErr != nil {
				t.Fatalf("Uninstall removed the other owned Goose file: %v", readErr)
			}
			if !bytes.Equal(preservedAfter, preservedBefore) {
				t.Fatal("Uninstall changed the other owned Goose file before preflight completed")
			}
			if got, readErr := os.ReadFile(malformedPath); readErr != nil || string(got) != "{" {
				t.Fatalf("Uninstall changed malformed Goose target: %q, %v", got, readErr)
			}
		})
	}
}

func TestClineUninstallPreflightsEveryHook(t *testing.T) {
	dir := t.TempDir()
	if _, err := Install(AgentCline, dir, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	preservedPath := clineHookPath(dir, clineHookEvents[0].name)
	preservedBefore, err := os.ReadFile(preservedPath)
	if err != nil {
		t.Fatal(err)
	}
	badPath := clineHookPath(dir, clineHookEvents[len(clineHookEvents)-1].name)
	if err := os.Remove(badPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := StatusErr(AgentCline, dir); err == nil {
		t.Fatal("StatusErr should reject a non-regular Cline hook")
	}
	rep, err := Uninstall(AgentCline, dir)
	if err == nil {
		t.Fatalf("Uninstall returned success for an uninspectable Cline hook: %+v", rep)
	}
	preservedAfter, readErr := os.ReadFile(preservedPath)
	if readErr != nil || !bytes.Equal(preservedAfter, preservedBefore) {
		t.Fatalf("Uninstall changed an earlier Cline hook before preflight completed: err=%v", readErr)
	}
}

func TestAuggieUninstallPreflightsEveryWrapper(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(AgentAuggie, settingsPath, auspexBinary, "", false); err != nil {
		t.Fatal(err)
	}
	settingsBefore, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	preservedPath := auggieScriptPath(settingsPath, auggieHookEvents[0].lifecycle)
	preservedBefore, err := os.ReadFile(preservedPath)
	if err != nil {
		t.Fatal(err)
	}
	badPath := auggieScriptPath(settingsPath, auggieHookEvents[len(auggieHookEvents)-1].lifecycle)
	if err := os.Remove(badPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := StatusErr(AgentAuggie, settingsPath); err == nil {
		t.Fatal("StatusErr should reject a non-regular Auggie wrapper")
	}
	rep, err := Uninstall(AgentAuggie, settingsPath)
	if err == nil {
		t.Fatalf("Uninstall returned success for an uninspectable Auggie wrapper: %+v", rep)
	}
	settingsAfter, readErr := os.ReadFile(settingsPath)
	if readErr != nil || !bytes.Equal(settingsAfter, settingsBefore) {
		t.Fatalf("Uninstall changed Auggie settings before wrapper preflight completed: err=%v", readErr)
	}
	preservedAfter, readErr := os.ReadFile(preservedPath)
	if readErr != nil || !bytes.Equal(preservedAfter, preservedBefore) {
		t.Fatalf("Uninstall changed an earlier Auggie wrapper before preflight completed: err=%v", readErr)
	}
}
