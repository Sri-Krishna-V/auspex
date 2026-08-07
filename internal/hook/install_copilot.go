package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Copilot CLI and VS Code share the flat hooks schema under ~/.copilot/hooks,
// so this installer reuses Cursor's lossless settings merge.

type copilotHookEvent struct {
	event     string
	lifecycle string
	timeout   int
}

type copilotHookEntry struct {
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeoutSec"`
}

// Lower-camel event names give Copilot CLI its native payload. VS Code loads the
// same file, converts these names to its PascalCase events, and emits its native
// snake_case payload; Map uses that shape to retain distinct source attribution.
var copilotHookEvents = []copilotHookEvent{
	{event: "sessionStart", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{event: "userPromptSubmitted", lifecycle: string(LifecyclePromptSubmit), timeout: promptHookTimeoutSeconds},
	{event: "preToolUse", lifecycle: string(LifecycleCopilotPreTool), timeout: fastHookTimeoutSeconds},
	{event: "postToolUse", lifecycle: string(LifecycleCopilotPostTool), timeout: fastHookTimeoutSeconds},
	{event: "postToolUseFailure", lifecycle: string(LifecycleCopilotPostTool), timeout: fastHookTimeoutSeconds},
	{event: "permissionRequest", lifecycle: string(LifecycleCopilotPermission), timeout: fastHookTimeoutSeconds},
	{event: "agentStop", lifecycle: string(LifecycleAssistant), timeout: stopHookTimeoutSeconds},
	{event: "subagentStart", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{event: "subagentStop", lifecycle: string(LifecycleSessionEnd), timeout: stopHookTimeoutSeconds},
	{event: "sessionEnd", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
}

// copilotCommandWithArgs builds the hook command auspex writes for a Copilot event. It
// passes the event's own name as the positional argument (resolved at runtime by
// ResolveLifecycle) and carries the auspex marker so detection survives a renamed
// binary. The binary path and runtime args are shell-quoted because the agent
// runs the command through a shell before auspex starts.
func copilotCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentCopilot, runtimeArgs, enforce)
}

// CopilotSettingsPath returns auspex's user-level Copilot CLI hook file under
// home. Copilot CLI and VS Code load this shared user directory (or
// $COPILOT_HOME/hooks/ when that environment variable is set). auspex installs
// one shared sensor by default; project (.github/hooks/*.json) and policy
// (/etc/github-copilot/policy.d/*.json on Unix) scopes can be targeted
// explicitly with --settings when the operator wants those upstream-supported
// layers.
func CopilotSettingsPath(home string) string {
	root := os.Getenv("COPILOT_HOME")
	if root == "" {
		root = filepath.Join(home, ".copilot")
	}
	return filepath.Join(root, "hooks", "auspex.json")
}

// installCopilotWithArgs wires auspex's hook entries into a Copilot hooks.json. It is
// idempotent and backs the pristine file up before the first write. It reuses the
// shared flat-schema settings handling (cursorSettings) since Copilot's schema
// matches Cursor's.
func installCopilotWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installCopilotAt(path, binary, runtimeArgs, false, enforce)
}

func installCopilotManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installCopilotAt(path, binary, runtimeArgs, true, enforce)
}

func installCopilotAt(path, binary string, runtimeArgs []string, managed, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCopilot, SettingsPath: path, Supported: true}
	cs, err := readCursorSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	for _, ev := range copilotHookEvents {
		kept := stripAuspexEntries(cs.hooks[ev.event])
		entry, err := json.Marshal(copilotHookEntry{
			Command:    copilotCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.event == "preToolUse"),
			TimeoutSec: ev.timeout,
		})
		if err != nil {
			return rep, err
		}
		cs.hooks[ev.event] = append(kept, json.RawMessage(entry))
	}
	data, err := cs.marshal()
	if err != nil {
		return rep, err
	}
	if err := writeHookConfig(path, data, managed); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = "installed auspex hooks"
	if managed {
		rep.Message = "installed auspex managed hooks"
	}
	if enforce {
		rep.Message += " (enforce mode: blocks matches from rules marked enforce=true)"
	}
	return rep, nil
}

// uninstallCopilot removes only auspex's entries from a Copilot hooks.json,
// leaving every other key and entry intact and a valid schema behind. A missing
// file or absent auspex entries is a no-op (Changed=false).
func uninstallCopilot(path string) (InstallReport, error) {
	return uninstallCopilotAt(path, false)
}

func uninstallCopilotManaged(path string) (InstallReport, error) {
	return uninstallCopilotAt(path, true)
}

func uninstallCopilotAt(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCopilot, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	cs, err := readCursorSettings(path)
	if err != nil {
		return rep, err
	}
	if !cs.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	data, err := cs.marshal()
	if err != nil {
		return rep, err
	}
	if err := writeHookConfig(path, data, managed); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	if managed {
		rep.Message = "removed auspex managed hooks"
	}
	return rep, nil
}

// statusCopilot reports whether auspex hooks are present in a Copilot hooks.json,
// without modifying anything.
func statusCopilot(path string) InstallReport {
	rep := InstallReport{Agent: AgentCopilot, SettingsPath: path, Supported: true}
	cs, err := readCursorSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = cs.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}
