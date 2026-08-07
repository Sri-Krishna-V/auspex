package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagedHooksPath(t *testing.T) {
	paths := make(map[string]string)
	for _, agent := range []string{AgentClaude, AgentCodex, AgentCursor, AgentCopilot, AgentGemini, AgentWindsurf, AgentQwen, AgentAuggie} {
		path, ok := ManagedHooksPath(agent)
		if !ok || path == "" {
			t.Fatalf("%s should expose a managed hooks path", agent)
		}
		paths[agent] = path
	}
	if runtime.GOOS == "darwin" && !strings.Contains(paths[AgentClaude], "/Library/Application Support/ClaudeCode/managed-settings.d/auspex.json") {
		t.Fatalf("Claude macOS managed path = %q", paths[AgentClaude])
	}
	if runtime.GOOS != "windows" && !strings.Contains(paths[AgentCodex], "/etc/codex/requirements.toml") {
		t.Fatalf("Codex Unix managed path = %q", paths[AgentCodex])
	}
	if _, ok := ManagedHooksPath(AgentVSCode); ok {
		t.Fatal("VS Code should not expose a first-class managed target")
	}
	if _, ok := ManagedHooksPath(AgentFactory); ok {
		t.Fatal("Factory should not expose an inferred managed file path")
	}
}

func TestManagedHooksPathWindows(t *testing.T) {
	paths := map[string]string{
		AgentClaude:   `C:/Program Files/ClaudeCode/managed-settings.d/auspex.json`,
		AgentCodex:    `C:/ProgramData/OpenAI/Codex/requirements.toml`,
		AgentCursor:   `C:/ProgramData/Cursor/hooks.json`,
		AgentCopilot:  `C:/ProgramData/GitHub/Copilot/policy.d/auspex.json`,
		AgentGemini:   `C:/ProgramData/gemini-cli/settings.json`,
		AgentWindsurf: `C:/ProgramData/Windsurf/hooks.json`,
		AgentQwen:     `C:/ProgramData/qwen-code/settings.json`,
		AgentAuggie:   `C:/ProgramData/Augment/settings.json`,
	}
	for agent, want := range paths {
		got, ok := managedHooksPath(agent, "windows", `C:\Program Files`, `C:\ProgramData`)
		got = strings.ReplaceAll(got, `\`, "/")
		if !ok || got != want {
			t.Errorf("managedHooksPath(%s, windows) = %q, %t; want %q, true", agent, got, ok, want)
		}
	}
}

func TestQwenManagedHooksPathHonorsOverride(t *testing.T) {
	setTestHome(t, t.TempDir())
	want := filepath.Join(t.TempDir(), "qwen-system.json")
	t.Setenv("QWEN_CODE_SYSTEM_SETTINGS_PATH", want)
	got, ok := ManagedHooksPath(AgentQwen)
	if !ok || got != want {
		t.Fatalf("ManagedHooksPath(qwen) = %q, %t; want %q, true", got, ok, want)
	}
}

func TestJSONManagedInstallLifecycle(t *testing.T) {
	for _, agent := range []string{AgentCursor, AgentCopilot, AgentGemini, AgentWindsurf, AgentQwen} {
		t.Run(agent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), agent, "managed.json")
			rep, err := InstallManagedWithOptions(agent, path, auspexBinary, InstallOptions{})
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			if !rep.Supported || !rep.Installed || !rep.Changed {
				t.Fatalf("install report = %+v", rep)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); !modeMatches(got, 0o644) {
				t.Fatalf("managed file mode = %o, want 644", got)
			}
			if agent == AgentCopilot {
				assertCopilotTimeouts(t, path)
			}
			status, err := StatusManagedErr(agent, path)
			if err != nil || !status.Installed {
				t.Fatalf("status = %+v, err=%v", status, err)
			}
			if _, err := InstallManagedWithOptions(agent, path, auspexBinary, InstallOptions{}); err != nil {
				t.Fatalf("idempotent reinstall: %v", err)
			}
			removed, err := UninstallManaged(agent, path)
			if err != nil || !removed.Changed {
				t.Fatalf("uninstall = %+v, err=%v", removed, err)
			}
			status, err = StatusManagedErr(agent, path)
			if err != nil || status.Installed {
				t.Fatalf("status after uninstall = %+v, err=%v", status, err)
			}
		})
	}
}

func TestAuggieManagedInstallWritesReadableSettingsAndScripts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "augment", "settings.json")
	rep, err := InstallManagedWithOptions(AgentAuggie, path, auspexBinary, InstallOptions{Enforce: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !Status(AgentAuggie, path).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentAuggie, path))
	}
	for _, event := range auggieHookEvents {
		info, err := os.Stat(auggieScriptPath(path, event.lifecycle))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && !modeMatches(info.Mode().Perm(), 0o755) {
			t.Errorf("managed Auggie script mode = %o, want 755", info.Mode().Perm())
		}
	}
	if removed, err := UninstallManaged(AgentAuggie, path); err != nil || !removed.Changed {
		t.Fatalf("uninstall = %+v, %v", removed, err)
	}
}

func assertCopilotTimeouts(t *testing.T, path string) {
	t.Helper()
	hooks := readCopilotHooks(t, path)
	for _, event := range copilotHookEvents {
		found := false
		for _, raw := range hooks[event.event] {
			if !entryIsAuspex(raw) {
				continue
			}
			found = true
			var entry copilotHookEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				t.Fatalf("decode %s hook: %v", event.event, err)
			}
			if entry.TimeoutSec != event.timeout {
				t.Errorf("event %q timeoutSec = %d, want %d", event.event, entry.TimeoutSec, event.timeout)
			}
		}
		if !found {
			t.Errorf("managed event %q has no auspex hook", event.event)
		}
	}
}

func TestClaudeManagedInstallWritesReadableDropIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.d", "auspex.json")
	rep, err := InstallManagedWithOptions(AgentClaude, path, auspexBinary, InstallOptions{})
	if err != nil {
		t.Fatalf("InstallManagedWithOptions: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported installed changed", rep)
	}
	if got, want := countAuspexHooks(readHooks(t, path)), len(claudeHookEvents); got != want {
		t.Fatalf("managed Claude hooks = %d, want %d", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat managed file: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o644) {
		t.Fatalf("managed file perm = %o, want 644 so user agent processes can read it", perm)
	}
}

func TestCodexManagedInstallWritesRequirements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	outFile := filepath.Join(t.TempDir(), "live.ndjson")
	rep, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{
		RuntimeArgs: []string{"--emit", "all", "--output=file", "--output-file", outFile},
	})
	if err != nil {
		t.Fatalf("InstallManagedWithOptions: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported installed changed", rep)
	}
	body := readText(t, path)
	commandText := hookCommandText(body)
	for _, want := range []string{
		codexAuspexFeatureBlockStart,
		"[features]",
		codexAuspexFeatureLine,
		codexAuspexHookBlockStart,
		"[[hooks.PreToolUse]]",
		"[[hooks.PreToolUse.hooks]]",
		"--agent codex",
		"--emit",
		"--output-file",
		outFile,
	} {
		if !strings.Contains(commandText, want) {
			t.Fatalf("requirements.toml missing %q:\n%s", want, body)
		}
	}
	if got := strings.Count(commandText, "--installed-by=auspex"); got != len(codexHookEvents) {
		t.Fatalf("installed codex managed hook commands = %d, want %d\n%s", got, len(codexHookEvents), body)
	}
	if got := strings.Count(body, "timeout = "); got != len(codexHookEvents) {
		t.Fatalf("installed codex managed hook timeouts = %d, want %d\n%s", got, len(codexHookEvents), body)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat requirements: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o644) {
		t.Fatalf("requirements perm = %o, want 644", perm)
	}
}

func TestCodexManagedStatusReportsReadError(t *testing.T) {
	path := t.TempDir()
	rep, err := StatusManagedErr(AgentCodex, path)
	if err == nil {
		t.Fatalf("StatusManagedErr(%q) = %+v, nil; want read error", path, rep)
	}
	if rep.Installed {
		t.Fatalf("StatusManagedErr(%q) = %+v; unreadable target cannot be installed", path, rep)
	}
}

func TestCodexManagedInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if _, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{}); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{}); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	body := readText(t, path)
	if got := strings.Count(body, codexAuspexHookBlockStart); got != 1 {
		t.Fatalf("auspex hook block count = %d, want 1\n%s", got, body)
	}
	if got := strings.Count(hookCommandText(body), "--installed-by=auspex"); got != len(codexHookEvents) {
		t.Fatalf("installed commands = %d, want %d\n%s", got, len(codexHookEvents), body)
	}
}

func TestCodexManagedInstallPreservesExistingRequirements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	seed := "[features]\nweb_search = false\n\nallowed_approval_policies = [\"on-request\"]\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{}); err != nil {
		t.Fatalf("InstallManagedWithOptions: %v", err)
	}
	body := readText(t, path)
	if !strings.Contains(body, "web_search = false") || !strings.Contains(body, "allowed_approval_policies") {
		t.Fatalf("existing requirements were not preserved:\n%s", body)
	}
	featuresStart := strings.Index(body, "[features]")
	featureLine := strings.Index(body, codexAuspexFeatureLine)
	if featuresStart == -1 || featureLine == -1 || featureLine < featuresStart {
		t.Fatalf("auspex feature line was not inserted into [features]:\n%s", body)
	}
}

func TestCodexManagedInstallRefusesHooksDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("[features]\nhooks = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "hooks=false") {
		t.Fatalf("InstallManagedWithOptions error = %v, want hooks=false refusal", err)
	}
}

func TestCodexManagedInstallReportsQuotedHooksValueWithHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("[features]\nhooks = \"true#managed\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), `"true#managed"`) {
		t.Fatalf("InstallManagedWithOptions error = %v, want full quoted value with # preserved", err)
	}
}

func TestCodexManagedInstallEscapesTOMLStrings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	binary := filepath.Join(t.TempDir(), "num\x07bat")
	out := filepath.Join(t.TempDir(), "live\x0b.ndjson")
	if _, err := InstallManagedWithOptions(AgentCodex, path, binary, InstallOptions{
		RuntimeArgs: []string{"--output-file", out},
	}); err != nil {
		t.Fatalf("InstallManagedWithOptions: %v", err)
	}
	body := readText(t, path)
	withoutEscapedBackslashes := strings.ReplaceAll(body, `\\`, "")
	if strings.Contains(withoutEscapedBackslashes, `\a`) || strings.Contains(withoutEscapedBackslashes, `\v`) {
		t.Fatalf("requirements.toml contains Go-only escapes:\n%s", body)
	}
	commandText := hookCommandText(body)
	if runtime.GOOS == "windows" {
		if !strings.Contains(commandText, binary) || !strings.Contains(commandText, out) {
			t.Fatalf("managed command lost control-character paths:\n%s", body)
		}
	} else {
		for _, want := range []string{`\u0007`, `\u000B`} {
			if !strings.Contains(body, want) {
				t.Fatalf("requirements.toml missing TOML escape %q:\n%s", want, body)
			}
		}
	}
}

func TestCodexManagedInstallThreadsEnforce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	rep, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{Enforce: true})
	if err != nil {
		t.Fatalf("InstallManagedWithOptions: %v", err)
	}
	if !strings.Contains(rep.Message, "enforce mode") {
		t.Fatalf("report message = %q, want enforce mode", rep.Message)
	}
	body := readText(t, path)
	if got := strings.Count(hookCommandText(body), "--enforce"); got != 1 {
		t.Fatalf("managed codex enforce flags = %d, want 1 in PreToolUse only\n%s", got, body)
	}
}

func TestCodexManagedUninstallRemovesOnlyAuspexBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	seed := "[features]\nhooks = true\nweb_search = false\n\nallowed_approval_policies = [\"on-request\"]\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallManagedWithOptions(AgentCodex, path, auspexBinary, InstallOptions{}); err != nil {
		t.Fatalf("install: %v", err)
	}
	rep, err := UninstallManaged(AgentCodex, path)
	if err != nil {
		t.Fatalf("UninstallManaged: %v", err)
	}
	if !rep.Changed {
		t.Fatal("uninstall should report a change")
	}
	body := readText(t, path)
	if strings.Contains(hookCommandText(body), "--installed-by=auspex") || strings.Contains(body, codexAuspexHookBlockStart) {
		t.Fatalf("auspex block remains after uninstall:\n%s", body)
	}
	for _, want := range []string{"hooks = true", "web_search = false", "allowed_approval_policies"} {
		if !strings.Contains(body, want) {
			t.Fatalf("uninstall dropped existing requirement %q:\n%s", want, body)
		}
	}
}

func TestCodexManagedUninstallWithoutAuspexIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	seed := "[features]\nhooks = true"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := UninstallManaged(AgentCodex, path)
	if err != nil {
		t.Fatalf("UninstallManaged: %v", err)
	}
	if rep.Changed {
		t.Fatalf("uninstall without auspex blocks should be no-op, got report %+v", rep)
	}
	if got := readText(t, path); got != seed {
		t.Fatalf("uninstall rewrote unrelated requirements: got %q want %q", got, seed)
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
