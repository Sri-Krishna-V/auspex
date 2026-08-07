package hook

import (
	"os"
	"path/filepath"
	"runtime"
)

// Codex and Claude share the nested matcher/hooks schema, so this installer
// reuses the lossless settings merge. Codex-specific event and path handling
// stays in this file.

// codexHookEvent is a Codex hooks.json event name paired with the auspex
// lifecycle argument its command invokes and an optional tool matcher.
type codexHookEvent struct {
	// settingsKey is the key under "hooks" in Codex's hooks.json.
	settingsKey string
	// lifecycle is the positional argument passed to `auspex hook <lifecycle>`.
	lifecycle string
	// matcher restricts which tools fire the hook; empty means all.
	matcher string
	// timeout is the hook's timeout in seconds; 0 omits it.
	timeout int
}

// codexHookEvents is the documented lifecycle subset auspex can normalize.
// Only PreToolUse may deny in enforce mode.
var codexHookEvents = []codexHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{settingsKey: "UserPromptSubmit", lifecycle: "prompt-submit", timeout: promptHookTimeoutSeconds},
	{settingsKey: "PreToolUse", lifecycle: "codex-pre-tool", matcher: ".*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUse", lifecycle: "codex-post-tool", matcher: ".*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PermissionRequest", lifecycle: string(LifecycleCodexPermission), matcher: ".*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "SubagentStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{settingsKey: "SubagentStop", lifecycle: "session-end", timeout: fastHookTimeoutSeconds},
	{settingsKey: "Stop", lifecycle: "stop", timeout: stopHookTimeoutSeconds},
}

// codexCommandWithArgs renders one command for Codex's string-only hook field.
func codexCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentCodex, runtimeArgs, enforce)
}

// CodexSettingsPath returns the user hook file under CODEX_HOME or ~/.codex.
func CodexSettingsPath(home string) string {
	root := os.Getenv("CODEX_HOME")
	if root == "" {
		root = filepath.Join(home, ".codex")
	}
	return filepath.Join(root, "hooks.json")
}

// applyAuspexGroupsForArgs is the shared nested-schema apply used by the Claude and
// Codex installers (their hooks.json schema is the same matcher/hooks-of-{type,
// command,timeout} shape). It writes one auspex group per event using the
// supplied command builder, stripping any prior auspex group first so a
// re-install stays idempotent and never duplicates. Non-auspex groups in the same
// event are left untouched.
func (sf settingsFile) applyAuspexGroupsForArgs(events []codexHookEvent, binary string, runtimeArgs []string, enforce bool, cmd func(binary, lifecycle string, runtimeArgs []string, enforce bool) string) {
	for _, ev := range events {
		groups := stripAuspexGroups(sf.hooks[ev.settingsKey])
		groups = append(groups, hookGroup{
			Matcher: ev.matcher,
			Hooks: []hookRef{{
				Type:    "command",
				Command: cmd(binary, ev.lifecycle, runtimeArgs, enforce && ev.settingsKey == "PreToolUse"),
				Timeout: ev.timeout,
			}},
		})
		sf.hooks[ev.settingsKey] = groups
	}
}

// installCodexWithArgs wires auspex's hook entries into a Codex hooks.json. It is
// idempotent and backs the pristine file up before the first write. It reuses the
// shared nested-schema settings handling (settingsFile) since Codex's schema
// matches Claude's.
func installCodexWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCodex, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	sf.applyAuspexGroupsForArgs(codexHookEvents, binary, runtimeArgs, enforce, codexCommandWithArgs)
	if err := writeCodexSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	if enforce {
		rep.Message = "installed auspex hooks (enforce mode: blocks PreToolUse matches from rules marked enforce=true; trust them in Codex via /hooks or app Settings > Hooks)"
	} else {
		rep.Message = "installed auspex hooks (observe-only; trust them in Codex via /hooks or app Settings > Hooks)"
	}
	return rep, nil
}

// uninstallCodex removes only auspex's entries from a Codex hooks.json, leaving
// every other key and group intact and a valid schema behind. A missing file or
// absent auspex entries is a no-op (Changed=false).
func uninstallCodex(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCodex, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	if !sf.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeCodexSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	return rep, nil
}

// statusCodex reports whether auspex hooks are present in a Codex hooks.json,
// without modifying anything.
func statusCodex(path string) InstallReport {
	rep := InstallReport{Agent: AgentCodex, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = sf.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

// writeCodexSettings renders and atomically writes a Codex hooks.json. Unlike
// Claude's writeSettings (which drops an empty hooks block), Codex's schema is
// {hooks:{...}}, so after an uninstall that removed the last entry the file must
// still carry a (possibly empty) hooks map rather than collapsing to an object
// with no hooks key — the same lesson as the Cursor/Windsurf installers. It
// shares writeFileAtomic for identical durability and 0600 permission guarantees.
func writeCodexSettings(path string, sf settingsFile) error {
	data, err := sf.marshalAlwaysHooks()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}
