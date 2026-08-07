package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	kiroHookFile       = "auspex.json"
	kiroHookNamePrefix = "auspex-"
)

type kiroHookAction struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type kiroHook struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Trigger     string         `json:"trigger"`
	Matcher     string         `json:"matcher,omitempty"`
	Action      kiroHookAction `json:"action"`
	Timeout     int            `json:"timeout,omitempty"`
	Enabled     bool           `json:"enabled"`
}

type kiroHookFileDocument struct {
	Version string     `json:"version"`
	Hooks   []kiroHook `json:"hooks"`
}

type kiroHookEvent struct {
	trigger   string
	lifecycle string
	timeout   int
}

var kiroHookEvents = []kiroHookEvent{
	{trigger: "SessionStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{trigger: "UserPromptSubmit", lifecycle: "prompt-submit", timeout: promptHookTimeoutSeconds},
	{trigger: "PreToolUse", lifecycle: "pre-tool", timeout: fastHookTimeoutSeconds},
	{trigger: "PostToolUse", lifecycle: "post-tool", timeout: fastHookTimeoutSeconds},
	{trigger: "Stop", lifecycle: "stop", timeout: stopHookTimeoutSeconds},
}

// KiroHooksPath returns Kiro's versioned global hook file. At the default
// ~/.kiro root, Kiro IDE 1.0.182+ and Kiro CLI 2.13+ v3 load this file.
// KIRO_HOME relocates the CLI global root; Kiro does not document that override
// for the IDE, so IDE coverage is claimed only for the default root.
func KiroHooksPath(home string) string {
	root := os.Getenv("KIRO_HOME")
	if root == "" {
		root = filepath.Join(home, ".kiro")
	}
	return filepath.Join(root, "hooks", kiroHookFile)
}

func kiroRuntimeCoverageNote(path string) string {
	home, err := os.UserHomeDir()
	defaultPath := filepath.Join(home, ".kiro", "hooks", kiroHookFile)
	if err == nil && sameKiroHookPath(path, defaultPath) {
		if root := os.Getenv("KIRO_HOME"); root != "" &&
			!sameKiroHookPath(defaultPath, filepath.Join(root, "hooks", kiroHookFile)) {
			return "loaded by Kiro IDE 1.0.182+; KIRO_HOME moves Kiro CLI to a separate root"
		}
		return "loaded by Kiro IDE 1.0.182+ at default ~/.kiro and by Kiro CLI 2.13+ with v3 enabled"
	}
	if root := os.Getenv("KIRO_HOME"); root != "" && sameKiroHookPath(path, filepath.Join(root, "hooks", kiroHookFile)) {
		return "loaded by Kiro CLI 2.13+ with v3 enabled; KIRO_HOME paths are not documented for Kiro IDE"
	}
	return "verify the selected Kiro host loads this explicit path; IDE coverage is documented at ~/.kiro/hooks and KIRO_HOME is CLI-only"
}

func sameKiroHookPath(got, want string) bool {
	gotAbs, gotErr := filepath.Abs(got)
	wantAbs, wantErr := filepath.Abs(want)
	return gotErr == nil && wantErr == nil && samePlatformPath(gotAbs, wantAbs)
}

func kiroHookDocument(binary string, runtimeArgs []string, enforce bool) kiroHookFileDocument {
	doc := kiroHookFileDocument{Version: "v1", Hooks: make([]kiroHook, 0, len(kiroHookEvents))}
	for _, event := range kiroHookEvents {
		command := buildHookCommand(runtime.GOOS, binary, event.lifecycle, AgentKiro, runtimeArgs, enforce && event.trigger == "PreToolUse")
		doc.Hooks = append(doc.Hooks, kiroHook{
			Name:        kiroHookNamePrefix + strings.ToLower(event.trigger),
			Description: "auspex endpoint activity monitor",
			Trigger:     event.trigger,
			Matcher:     kiroMatcher(event.trigger),
			Action:      kiroHookAction{Type: "command", Command: command},
			Timeout:     event.timeout,
			Enabled:     true,
		})
	}
	return doc
}

func kiroMatcher(trigger string) string {
	if trigger == "PreToolUse" || trigger == "PostToolUse" {
		return ".*"
	}
	return ""
}

func readKiroHookFile(path string) (kiroHookFileDocument, error) {
	doc, _, err := readKiroHookFileIfExists(path)
	return doc, err
}

func readKiroHookFileIfExists(path string) (kiroHookFileDocument, bool, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return kiroHookFileDocument{}, false, nil
		}
		return kiroHookFileDocument{}, false, err
	}
	var doc kiroHookFileDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return kiroHookFileDocument{}, true, fmt.Errorf("parse Kiro hook file %s: %w", path, err)
	}
	return doc, true, nil
}

func isAuspexKiroHookFile(path string) bool {
	doc, err := readKiroHookFile(path)
	return err == nil && isAuspexKiroHookDocument(doc)
}

func isAuspexKiroHookDocument(doc kiroHookFileDocument) bool {
	if doc.Version != "v1" || len(doc.Hooks) != len(kiroHookEvents) {
		return false
	}
	expected := make(map[string]kiroHookEvent, len(kiroHookEvents))
	for _, event := range kiroHookEvents {
		expected[event.trigger] = event
	}
	for _, entry := range doc.Hooks {
		event, ok := expected[entry.Trigger]
		if !ok || entry.Name != kiroHookNamePrefix+strings.ToLower(entry.Trigger) || entry.Action.Type != "command" ||
			entry.Matcher != kiroMatcher(entry.Trigger) || entry.Timeout != event.timeout || !entry.Enabled ||
			!isAuspexHookCommand(entry.Action.Command) {
			return false
		}
		delete(expected, entry.Trigger)
	}
	return len(expected) == 0
}

func installKiroWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentKiro, SettingsPath: path, Supported: true}
	doc, exists, err := readKiroHookFileIfExists(path)
	if err != nil {
		return rep, err
	}
	if exists && !isAuspexKiroHookDocument(doc) {
		return rep, fmt.Errorf("refusing to overwrite existing non-auspex Kiro hook file at %s", path)
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	data, err := json.MarshalIndent(kiroHookDocument(binary, runtimeArgs, enforce), "", "  ")
	if err != nil {
		return rep, fmt.Errorf("marshal Kiro hook file: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(path, data); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed auspex Kiro global hooks (" + kiroRuntimeCoverageNote(path) + ")"
	if enforce {
		rep.Message = "installed auspex Kiro global hooks in enforce mode (" + kiroRuntimeCoverageNote(path) + ")"
	}
	return rep, nil
}

func uninstallKiro(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentKiro, SettingsPath: path, Supported: true}
	doc, exists, err := readKiroHookFileIfExists(path)
	if err != nil {
		return rep, err
	}
	if !exists {
		rep.Message = "no hook file; nothing to remove"
		return rep, nil
	}
	if !isAuspexKiroHookDocument(doc) {
		rep.Message = "hook file is not auspex-owned; leaving it untouched"
		return rep, nil
	}
	if err := os.Remove(path); err != nil {
		return rep, err
	}
	rep.Changed, rep.Message = true, "removed auspex Kiro global hooks"
	return rep, nil
}

func statusKiro(path string) InstallReport {
	rep := InstallReport{Agent: AgentKiro, SettingsPath: path, Supported: true, Installed: isAuspexKiroHookFile(path)}
	if rep.Installed {
		rep.Message = "auspex Kiro global hooks installed; " + kiroRuntimeCoverageNote(path)
	} else {
		rep.Message = "auspex Kiro global hooks not installed"
	}
	return rep
}
