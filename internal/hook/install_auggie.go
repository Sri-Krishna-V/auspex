package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type auggieHookEvent struct {
	settingsKey string
	lifecycle   string
	matcher     string
	timeoutMs   int
}

var auggieHookEvents = []auggieHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "PreToolUse", lifecycle: "pre-tool", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "PostToolUse", lifecycle: "post-tool", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "Stop", lifecycle: "stop", timeoutMs: stopHookTimeoutSeconds * 1000},
	{settingsKey: "SessionEnd", lifecycle: "session-end", timeoutMs: fastHookTimeoutSeconds * 1000},
}

func AuggieSettingsPath(home string) string {
	return filepath.Join(home, ".augment", "settings.json")
}

func auggieScriptPath(settingsPath, lifecycle string) string {
	ext := ".sh"
	if runtime.GOOS == "windows" {
		ext = ".ps1"
	}
	name := "auspex--installed-by=auspex-" + strings.ReplaceAll(lifecycle, "-", "_") + ext
	return filepath.Join(filepath.Dir(settingsPath), "hooks", name)
}

func auggieScriptSource(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	args := hookInvocationArgs(lifecycle, AgentAuggie, runtimeArgs, enforce)
	if runtime.GOOS == "windows" {
		var b strings.Builder
		b.WriteString("# auspex-managed Auggie hook - do not edit\r\n$global:LASTEXITCODE = 1\r\n$payload = [Console]::In.ReadToEnd()\r\n$null = $payload | & ")
		b.WriteString(powerShellQuote(binary))
		for _, arg := range args {
			b.WriteByte(' ')
			b.WriteString(powerShellQuote(arg))
		}
		b.WriteString("\r\n$exitCode = $LASTEXITCODE\r\nexit $exitCode\r\n")
		return b.String()
	}
	cmd := "exec " + shellQuote(binary)
	for _, arg := range args {
		cmd += " " + shellQuote(arg)
	}
	return "#!/bin/sh\n# auspex-managed Auggie hook - do not edit\n" + cmd + " >/dev/null\n"
}

func isAuspexAuggieScript(path string) bool {
	_, owned, err := auggieScriptOwnership(path)
	return err == nil && owned
}

func auggieScriptOwnership(path string) (exists, owned bool, err error) {
	return textHookFileOwnership(path, "auspex-managed Auggie hook")
}

func configReadableAuggie(path string) error {
	if _, err := readSettings(path); err != nil {
		return err
	}
	for _, event := range auggieHookEvents {
		if _, _, err := auggieScriptOwnership(auggieScriptPath(path, event.lifecycle)); err != nil {
			return err
		}
	}
	return nil
}

func isAuspexAuggieHookRef(settingsPath string, ref hookRef) bool {
	command := filepath.Clean(ref.Command)
	for _, event := range auggieHookEvents {
		owned := filepath.Clean(auggieScriptPath(settingsPath, event.lifecycle))
		if command == owned || (runtime.GOOS == "windows" && strings.EqualFold(command, owned)) {
			return true
		}
	}
	return false
}

func stripAuspexAuggieGroups(settingsPath string, groups []hookGroup) []hookGroup {
	out := make([]hookGroup, 0, len(groups))
	for _, group := range groups {
		kept := group.Hooks[:0:0]
		for _, ref := range group.Hooks {
			if !isAuspexAuggieHookRef(settingsPath, ref) {
				kept = append(kept, ref)
			}
		}
		if len(kept) > 0 {
			group.Hooks = kept
			out = append(out, group)
		}
	}
	return out
}

func auggieHookState(sf settingsFile, settingsPath string) (complete, any bool) {
	complete = true
	for _, groups := range sf.hooks {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				if isAuspexAuggieHookRef(settingsPath, ref) {
					any = true
				}
			}
		}
	}
	for _, event := range auggieHookEvents {
		present := false
		for _, group := range sf.hooks[event.settingsKey] {
			for _, ref := range group.Hooks {
				present = present || isAuspexAuggieHookRef(settingsPath, ref)
			}
		}
		complete = complete && present
	}
	return complete, any
}

func hasAuspexAuggieHooks(sf settingsFile, settingsPath string) bool {
	_, any := auggieHookState(sf, settingsPath)
	return any
}

func removeAuspexAuggieHooks(sf settingsFile, settingsPath string) bool {
	changed := false
	for key, groups := range sf.hooks {
		keptGroups := make([]hookGroup, 0, len(groups))
		for _, group := range groups {
			keptRefs := group.Hooks[:0:0]
			for _, ref := range group.Hooks {
				if isAuspexAuggieHookRef(settingsPath, ref) {
					changed = true
					continue
				}
				keptRefs = append(keptRefs, ref)
			}
			if len(keptRefs) > 0 {
				group.Hooks = keptRefs
				keptGroups = append(keptGroups, group)
			}
		}
		if len(keptGroups) == 0 {
			delete(sf.hooks, key)
		} else {
			sf.hooks[key] = keptGroups
		}
	}
	return changed
}

func applyAuggieHooks(sf settingsFile, path, binary string, runtimeArgs []string, enforce bool) (settingsFile, error) {
	for _, event := range auggieHookEvents {
		script := auggieScriptPath(path, event.lifecycle)
		exists, owned, err := auggieScriptOwnership(script)
		if err != nil {
			return sf, err
		}
		if exists && !owned {
			return sf, fmt.Errorf("refusing to overwrite existing non-auspex file at %s", script)
		}
		groups := stripAuspexAuggieGroups(path, sf.hooks[event.settingsKey])
		groups = append(groups, hookGroup{
			Matcher: event.matcher,
			Hooks:   []hookRef{{Type: "command", Command: script, Timeout: event.timeoutMs}},
		})
		sf.hooks[event.settingsKey] = groups
	}
	return sf, nil
}

func writeAuggieScripts(path, binary string, runtimeArgs []string, enforce, managed bool) error {
	mode := os.FileMode(0o700)
	if managed {
		mode = 0o755
	}
	for _, event := range auggieHookEvents {
		script := auggieScriptPath(path, event.lifecycle)
		source := auggieScriptSource(binary, event.lifecycle, runtimeArgs, enforce && event.settingsKey == "PreToolUse")
		if err := writeFileAtomicMode(script, []byte(source), mode, mode); err != nil {
			return err
		}
	}
	return nil
}

func installAuggieWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installAuggieWithArgsMode(path, binary, runtimeArgs, enforce, false)
}

func installAuggieManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installAuggieWithArgsMode(path, binary, runtimeArgs, enforce, true)
}

func installAuggieWithArgsMode(path, binary string, runtimeArgs []string, enforce, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentAuggie, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		return rep, fmt.Errorf("parse Auggie settings (comments and trailing commas must be removed before automatic install): %w", err)
	}
	sf, err = applyAuggieHooks(sf, path, binary, runtimeArgs, enforce)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeAuggieScripts(path, binary, runtimeArgs, enforce, managed); err != nil {
		return rep, err
	}
	if err := writeAuggieSettings(path, sf, managed); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = installMessage(enforce)
	if managed {
		rep.Message = strings.Replace(rep.Message, "installed", "installed managed", 1)
	}
	return rep, nil
}

func uninstallAuggie(path string) (InstallReport, error) {
	return uninstallAuggieMode(path, false)
}

func uninstallAuggieManaged(path string) (InstallReport, error) {
	return uninstallAuggieMode(path, true)
}

func uninstallAuggieMode(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentAuggie, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	ownedScripts := make([]string, 0, len(auggieHookEvents))
	for _, event := range auggieHookEvents {
		script := auggieScriptPath(path, event.lifecycle)
		_, owned, err := auggieScriptOwnership(script)
		if err != nil {
			return rep, err
		}
		if owned {
			ownedScripts = append(ownedScripts, script)
		}
	}
	configChanged := removeAuspexAuggieHooks(sf, path)
	if configChanged {
		backup, err := backupIfExists(path)
		if err != nil {
			return rep, err
		}
		rep.BackupPath = backup
		if err := writeAuggieSettings(path, sf, managed); err != nil {
			return rep, err
		}
	}
	scriptsChanged := false
	for _, script := range ownedScripts {
		if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
			return rep, err
		}
		scriptsChanged = true
	}
	rep.Changed = configChanged || scriptsChanged
	if rep.Changed {
		rep.Message = "removed auspex hooks and wrapper scripts"
		if managed {
			rep.Message = "removed auspex managed hooks and wrapper scripts"
		}
	} else {
		rep.Message = "no auspex hooks present"
	}
	return rep, nil
}

func statusAuggie(path string) InstallReport {
	rep := InstallReport{Agent: AgentAuggie, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	installedScripts := 0
	for _, event := range auggieHookEvents {
		if isAuspexAuggieScript(auggieScriptPath(path, event.lifecycle)) {
			installedScripts++
		}
	}
	completeConfig, anyConfig := auggieHookState(sf, path)
	rep.Installed = completeConfig && installedScripts == len(auggieHookEvents)
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else if anyConfig || installedScripts > 0 {
		rep.Message = fmt.Sprintf("partial auspex Auggie install (%d/%d wrapper scripts)", installedScripts, len(auggieHookEvents))
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

func writeAuggieSettings(path string, sf settingsFile, managed bool) error {
	if managed {
		return writeManagedSettings(path, sf)
	}
	return writeSettings(path, sf)
}
