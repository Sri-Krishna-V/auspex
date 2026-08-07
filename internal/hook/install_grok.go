package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const grokManagedFile = "auspex.json"

type grokHookEvent struct {
	eventKey  string
	lifecycle string
	timeout   int
}

var grokHookEvents = []grokHookEvent{
	{eventKey: "SessionStart", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{eventKey: "UserPromptSubmit", lifecycle: string(LifecyclePromptSubmit), timeout: promptHookTimeoutSeconds},
	{eventKey: "PreToolUse", lifecycle: string(LifecycleGrokPreTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "PostToolUse", lifecycle: string(LifecycleGrokPostTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "PostToolUseFailure", lifecycle: string(LifecycleGrokPostTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "PermissionDenied", lifecycle: string(LifecyclePermissionDenied), timeout: fastHookTimeoutSeconds},
	{eventKey: "SubagentStart", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{eventKey: "SubagentStop", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
	{eventKey: "Stop", lifecycle: string(LifecycleStop), timeout: stopHookTimeoutSeconds},
	{eventKey: "SessionEnd", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
}

type grokHooks map[string][]hookGroup

type grokFile struct {
	exists  bool
	foreign map[string]json.RawMessage
	hooks   grokHooks
}

// GrokHooksDir returns Grok Build's personal hook directory. GROK_HOME
// relocates Grok's entire user root, including hooks.
func GrokHooksDir(home string) string {
	root := os.Getenv("GROK_HOME")
	if root == "" {
		root = filepath.Join(home, ".grok")
	}
	return filepath.Join(root, "hooks")
}

func GrokHooksPath(home string) string {
	return filepath.Join(GrokHooksDir(home), grokManagedFile)
}

func grokCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentGrok, runtimeArgs, enforce)
}

func readGrokFile(path string) (grokFile, error) {
	gf := grokFile{foreign: map[string]json.RawMessage{}}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return gf, nil
		}
		return grokFile{}, err
	}
	gf.exists = true
	if len(data) == 0 {
		return gf, nil
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return grokFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	for key, raw := range top {
		if key != "hooks" {
			gf.foreign[key] = raw
			continue
		}
		if err := json.Unmarshal(raw, &gf.hooks); err != nil {
			return grokFile{}, fmt.Errorf("parse hooks in %s: %w", path, err)
		}
	}
	return gf, nil
}

func (gf grokFile) hasAuspexHooks() bool {
	for _, groups := range gf.hooks {
		if hasAuspexGroup(groups) {
			return true
		}
	}
	return false
}

func (gf *grokFile) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	if gf.hooks == nil {
		gf.hooks = grokHooks{}
	}
	for _, event := range grokHookEvents {
		groups := stripAuspexGroups(gf.hooks[event.eventKey])
		groups = append(groups, hookGroup{Hooks: []hookRef{{
			Type:    "command",
			Command: grokCommandWithArgs(binary, event.lifecycle, runtimeArgs, enforce && event.eventKey == "PreToolUse"),
			Timeout: event.timeout,
		}}})
		gf.hooks[event.eventKey] = groups
	}
	gf.exists = true
}

func (gf *grokFile) removeAuspexHooks() bool {
	changed := false
	for key, groups := range gf.hooks {
		if hasAuspexGroup(groups) {
			changed = true
		}
		kept := stripAuspexGroups(groups)
		if len(kept) == 0 {
			delete(gf.hooks, key)
		} else {
			gf.hooks[key] = kept
		}
	}
	return changed
}

func (gf grokFile) isEmpty() bool {
	return len(gf.foreign) == 0 && len(gf.hooks) == 0
}

func (gf grokFile) marshal() ([]byte, error) {
	top := make(map[string]json.RawMessage, len(gf.foreign)+1)
	for key, raw := range gf.foreign {
		top[key] = raw
	}
	if len(gf.hooks) > 0 {
		raw, err := json.Marshal(gf.hooks)
		if err != nil {
			return nil, err
		}
		top["hooks"] = raw
	}
	return json.MarshalIndent(top, "", "  ")
}

func installGrokWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentGrok, SettingsPath: path, Supported: true}
	gf, err := readGrokFile(path)
	if err != nil {
		return rep, err
	}
	if gf.exists && !gf.isEmpty() && !gf.hasAuspexHooks() {
		return rep, fmt.Errorf("refusing to overwrite non-auspex hook file %s", path)
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	gf.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeGrokFile(path, gf); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = grokWithProjectNote(path, installMessage(enforce))
	return rep, nil
}

func uninstallGrok(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentGrok, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no hooks file; nothing to remove"
		return rep, nil
	}
	gf, err := readGrokFile(path)
	if err != nil {
		return rep, err
	}
	if !gf.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if gf.isEmpty() {
		if err := os.Remove(path); err != nil {
			return rep, err
		}
	} else if err := writeGrokFile(path, gf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	return rep, nil
}

func statusGrok(path string) InstallReport {
	rep := InstallReport{Agent: AgentGrok, SettingsPath: path, Supported: true}
	gf, err := readGrokFile(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = gf.hasAuspexHooks()
	if rep.Installed {
		rep.Message = grokWithProjectNote(path, "auspex hooks installed")
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

func writeGrokFile(path string, gf grokFile) error {
	data, err := gf.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

const grokProjectTrustNote = "run /hooks-trust in Grok before project hooks execute"

func grokWithProjectNote(path, message string) string {
	if isGrokProjectScope(path) {
		return message + "; " + grokProjectTrustNote
	}
	return message
}

func isGrokProjectScope(path string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	want, err := filepath.Abs(GrokHooksDir(home))
	if err != nil {
		return false
	}
	return !samePlatformPath(filepath.Dir(abs), want)
}

func GrokLifecycleArgs() []string {
	out := make([]string, 0, len(grokHookEvents))
	for _, event := range grokHookEvents {
		out = append(out, event.lifecycle)
	}
	return out
}
