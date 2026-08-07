package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// OpenHands accepts both its native flat snake_case hook map and the Claude
// Code-compatible {"hooks": {PascalCase: ...}} form. Auspex writes the latter
// so it can preserve unrelated top-level fields and foreign hooks with the same
// lossless settings editor used by other compatible command-hook surfaces.
var openHandsHookEvents = []claudeHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "UserPromptSubmit", lifecycle: "prompt-submit", matcher: "*", timeout: promptHookTimeoutSeconds},
	{settingsKey: "PreToolUse", lifecycle: "pre-tool", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUse", lifecycle: "post-tool", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "Stop", lifecycle: "stop", matcher: "*", timeout: stopHookTimeoutSeconds},
	{settingsKey: "SessionEnd", lifecycle: "session-end", matcher: "*", timeout: fastHookTimeoutSeconds},
}

func applyOpenHandsHooks(sf settingsFile, binary string, runtimeArgs []string, enforce bool) {
	for _, event := range openHandsHookEvents {
		groups := stripAuspexGroups(sf.hooks[event.settingsKey])
		groups = append(groups, hookGroup{
			Matcher: event.matcher,
			Hooks: []hookRef{{
				Type: "command",
				Command: buildHookCommand(
					runtime.GOOS,
					binary,
					event.lifecycle,
					AgentOpenHands,
					runtimeArgs,
					enforce && event.settingsKey == "PreToolUse",
				),
				Timeout: event.timeout,
			}},
		})
		sf.hooks[event.settingsKey] = groups
	}
}

func openHandsHookState(sf settingsFile) (complete, any bool) {
	complete = true
	for _, event := range openHandsHookEvents {
		present := hasAuspexGroup(sf.hooks[event.settingsKey])
		complete = complete && present
		any = any || present
	}
	return complete, any
}

func installOpenHandsWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentOpenHands, SettingsPath: path, Supported: true}
	if err := validateOpenHandsPath(path); err != nil {
		return rep, err
	}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	applyOpenHandsHooks(sf, binary, runtimeArgs, enforce)
	if err := writeSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed auspex OpenHands repository hooks"
	if enforce {
		rep.Message += " in enforce mode"
	}
	return rep, nil
}

func uninstallOpenHands(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentOpenHands, SettingsPath: path, Supported: true}
	if err := validateOpenHandsPath(path); err != nil {
		return rep, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no OpenHands hooks file; nothing to remove"
		return rep, nil
	}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	if !sf.removeAuspexHooks() {
		rep.Message = "no auspex OpenHands hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Changed, rep.Message = true, "removed auspex OpenHands repository hooks"
	return rep, nil
}

func statusOpenHands(path string) InstallReport {
	rep := InstallReport{Agent: AgentOpenHands, SettingsPath: path, Supported: true}
	if err := validateOpenHandsPath(path); err != nil {
		rep.Message = err.Error()
		return rep
	}
	sf, err := readSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	complete, any := openHandsHookState(sf)
	rep.Installed = complete
	if complete {
		rep.Message = "auspex OpenHands repository hooks installed"
	} else if any {
		rep.Message = "partial auspex OpenHands repository hook install"
	} else {
		rep.Message = "auspex OpenHands repository hooks not installed"
	}
	return rep
}

func validateOpenHandsPath(path string) error {
	if path == "" || !openHandsPathComponent(filepath.Base(path), "hooks.json") ||
		!openHandsPathComponent(filepath.Base(filepath.Dir(path)), ".openhands") {
		return fmt.Errorf("OpenHands requires an explicit repository .openhands/hooks.json path")
	}
	return nil
}

func openHandsPathComponent(got, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(got, want)
	}
	return got == want
}
