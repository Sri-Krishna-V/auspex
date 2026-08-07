package hook

import (
	"os"
	"path/filepath"
	"runtime"
)

const junieSessionEndTimeoutSeconds = 2

type junieHookEvent struct {
	settingsKey string
	lifecycle   string
	timeout     int
}

// junieHookEvents contains the Junie Early Access callbacks that can be
// observed without changing agent permission behavior and that map honestly to
// auspex's event model. PermissionRequest is intentionally absent because a
// matching command that exits 0 without a deny auto-approves the action.
// StopFailure is LLM/API health telemetry rather than an agent action and has no
// normalized event type yet.
var junieHookEvents = []junieHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{settingsKey: "UserPromptSubmit", lifecycle: "prompt-submit", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PreToolUse", lifecycle: "pre-tool", timeout: fastHookTimeoutSeconds},
	{settingsKey: "Stop", lifecycle: "stop", timeout: stopHookTimeoutSeconds},
	{settingsKey: "SessionEnd", lifecycle: "session-end", timeout: junieSessionEndTimeoutSeconds},
}

// JunieConfigPath returns the user hook configuration loaded by Junie CLI.
func JunieConfigPath(home string) string {
	return filepath.Join(home, ".junie", "config.json")
}

func applyAuspexJunieHooks(sf settingsFile, binary string, runtimeArgs []string, enforce bool) {
	sf.removeAuspexHooks()
	for _, event := range junieHookEvents {
		groups := sf.hooks[event.settingsKey]
		groups = append(groups, hookGroup{Hooks: []hookRef{{
			Type:    "command",
			Command: buildHookCommand(runtime.GOOS, binary, event.lifecycle, AgentJunie, runtimeArgs, enforce && event.settingsKey == "PreToolUse"),
			Timeout: event.timeout,
		}}})
		sf.hooks[event.settingsKey] = groups
	}
}

func junieHookState(sf settingsFile) (complete, any bool) {
	complete = true
	any = sf.hasAuspexHooks()
	for _, event := range junieHookEvents {
		complete = complete && hasAuspexGroup(sf.hooks[event.settingsKey])
	}
	return complete, any
}

func installJunieWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentJunie, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	applyAuspexJunieHooks(sf, binary, runtimeArgs, enforce)
	if err := writeSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed Junie CLI Early Access hooks (restart Junie)"
	if enforce {
		rep.Message = "installed Junie CLI Early Access hooks in enforce mode (restart Junie)"
	}
	return rep, nil
}

func uninstallJunie(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentJunie, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no Junie config; nothing to remove"
		return rep, nil
	}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	if !sf.removeAuspexHooks() {
		rep.Message = "no auspex Junie hooks present"
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
	rep.Changed = true
	rep.Message = "removed auspex Junie hooks (restart Junie)"
	return rep, nil
}

func statusJunie(path string) InstallReport {
	rep := InstallReport{Agent: AgentJunie, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	complete, any := junieHookState(sf)
	rep.Installed = complete
	if complete {
		rep.Message = "auspex Junie CLI Early Access hooks installed"
	} else if any {
		rep.Message = "partial auspex Junie CLI Early Access hook install"
	} else {
		rep.Message = "auspex Junie CLI Early Access hooks not installed"
	}
	return rep
}
