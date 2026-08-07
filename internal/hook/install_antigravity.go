package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const antigravityHookKey = "auspex"

type antigravityHookEvent struct {
	eventKey  string
	lifecycle string
	timeout   int
}

// Antigravity has no prompt or session-start hook. Pre/PostInvocation are model
// loop boundaries, so auspex omits them instead of labeling them as user prompts.
var antigravityHookEvents = []antigravityHookEvent{
	{eventKey: "PreToolUse", lifecycle: string(LifecycleAntigravityPreTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "PostToolUse", lifecycle: string(LifecycleAntigravityPostTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "Stop", lifecycle: string(LifecycleStop), timeout: stopHookTimeoutSeconds},
}

// Antigravity nests tool handlers under matcher groups, while Stop is a direct
// handler list. Keep the two shapes explicit so the generated JSON follows the
// upstream contract.
type antigravityDefinition struct {
	PreToolUse  []hookGroup `json:"PreToolUse,omitempty"`
	PostToolUse []hookGroup `json:"PostToolUse,omitempty"`
	Stop        []hookRef   `json:"Stop,omitempty"`
}

type antigravityFile struct {
	foreign       map[string]json.RawMessage
	auspex        antigravityDefinition
	auspexPresent bool
}

// AntigravityHooksPath returns the documented global hook file. Project hook
// files such as <project>/.agents/hooks.json can be selected with --settings.
func AntigravityHooksPath(home string) string {
	return filepath.Join(home, ".gemini", "config", "hooks.json")
}

func antigravityCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentAntigravity, runtimeArgs, enforce)
}

func readAntigravityFile(path string) (antigravityFile, error) {
	af := antigravityFile{foreign: map[string]json.RawMessage{}}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return af, nil
		}
		return antigravityFile{}, err
	}
	if len(data) == 0 {
		return af, nil
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return antigravityFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	for key, raw := range top {
		if key != antigravityHookKey {
			af.foreign[key] = raw
			continue
		}
		af.auspexPresent = true
		if err := json.Unmarshal(raw, &af.auspex); err != nil {
			return antigravityFile{}, fmt.Errorf("parse %s definition in %s: %w", antigravityHookKey, path, err)
		}
	}
	return af, nil
}

func (af antigravityFile) hasAuspexHooks() bool {
	for _, groups := range [][]hookGroup{af.auspex.PreToolUse, af.auspex.PostToolUse} {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				if isAuspexHookCommand(ref.Command) {
					return true
				}
			}
		}
	}
	for _, ref := range af.auspex.Stop {
		if isAuspexHookCommand(ref.Command) {
			return true
		}
	}
	return false
}

func (af *antigravityFile) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	ref := func(event antigravityHookEvent) hookRef {
		return hookRef{
			Type:    "command",
			Command: antigravityCommandWithArgs(binary, event.lifecycle, runtimeArgs, enforce && event.eventKey == "PreToolUse"),
			Timeout: event.timeout,
		}
	}
	toolGroup := func(event antigravityHookEvent) []hookGroup {
		return []hookGroup{{Matcher: "*", Hooks: []hookRef{ref(event)}}}
	}

	af.auspex = antigravityDefinition{
		PreToolUse:  toolGroup(antigravityHookEvents[0]),
		PostToolUse: toolGroup(antigravityHookEvents[1]),
		Stop:        []hookRef{ref(antigravityHookEvents[2])},
	}
	af.auspexPresent = true
}

func (af *antigravityFile) removeAuspexHooks() bool {
	if !af.hasAuspexHooks() {
		return false
	}
	af.auspex = antigravityDefinition{}
	af.auspexPresent = false
	return true
}

func (af antigravityFile) isEmpty() bool {
	return !af.auspexPresent && len(af.foreign) == 0
}

func (af antigravityFile) marshal() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(af.foreign)+1)
	for key, raw := range af.foreign {
		out[key] = raw
	}
	if af.auspexPresent {
		raw, err := json.Marshal(af.auspex)
		if err != nil {
			return nil, err
		}
		out[antigravityHookKey] = raw
	}
	return json.MarshalIndent(out, "", "  ")
}

func installAntigravityWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentAntigravity, SettingsPath: path, Supported: true}
	af, err := readAntigravityFile(path)
	if err != nil {
		return rep, err
	}
	if af.auspexPresent && !af.hasAuspexHooks() {
		return rep, fmt.Errorf("refusing to replace non-auspex hook definition %q in %s", antigravityHookKey, path)
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	af.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeAntigravityFile(path, af); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = installMessage(enforce)
	return rep, nil
}

func uninstallAntigravity(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentAntigravity, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no hooks file; nothing to remove"
		return rep, nil
	}
	af, err := readAntigravityFile(path)
	if err != nil {
		return rep, err
	}
	if !af.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if af.isEmpty() {
		if err := os.Remove(path); err != nil {
			return rep, err
		}
	} else if err := writeAntigravityFile(path, af); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	return rep, nil
}

func statusAntigravity(path string) InstallReport {
	rep := InstallReport{Agent: AgentAntigravity, SettingsPath: path, Supported: true}
	af, err := readAntigravityFile(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = af.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

func writeAntigravityFile(path string, af antigravityFile) error {
	data, err := af.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func AntigravityLifecycleArgs() []string {
	out := make([]string, 0, len(antigravityHookEvents))
	for _, event := range antigravityHookEvents {
		out = append(out, event.lifecycle)
	}
	return out
}
