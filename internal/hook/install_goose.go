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
	gooseManifestFile = "plugin.json"
	gooseHooksFile    = "hooks.json"
	goosePluginMarker = "auspex-managed Goose hook plugin"
)

type gooseHookEvent struct {
	event     string
	lifecycle string
	matcher   string
	timeout   int
}

var gooseHookEvents = []gooseHookEvent{
	{event: "SessionStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{event: "UserPromptSubmit", lifecycle: "prompt-submit", timeout: promptHookTimeoutSeconds},
	{event: "PreToolUse", lifecycle: "pre-tool", matcher: ".*", timeout: fastHookTimeoutSeconds},
	{event: "PostToolUse", lifecycle: "post-tool", matcher: ".*", timeout: fastHookTimeoutSeconds},
	{event: "PostToolUseFailure", lifecycle: "post-tool", matcher: ".*", timeout: fastHookTimeoutSeconds},
	{event: "Stop", lifecycle: "stop", timeout: stopHookTimeoutSeconds},
	{event: "SessionEnd", lifecycle: "session-end", timeout: fastHookTimeoutSeconds},
}

type goosePluginManifest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type gooseHookRef struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}

type gooseHookGroup struct {
	Matcher string         `json:"matcher,omitempty"`
	Hooks   []gooseHookRef `json:"hooks"`
}

type gooseHooksDocument struct {
	Hooks map[string][]gooseHookGroup `json:"hooks"`
}

// GoosePluginPath returns the user plugin directory from Goose's Open Plugins
// discovery contract.
func GoosePluginPath(home string) string {
	return filepath.Join(home, ".agents", "plugins", "auspex")
}

func gooseManifestPath(root string) string { return filepath.Join(root, gooseManifestFile) }

func gooseHooksPath(root string) string { return filepath.Join(root, "hooks", gooseHooksFile) }

func gooseCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentGoose, runtimeArgs, enforce)
}

func gooseDocuments(binary string, runtimeArgs []string, enforce bool) (goosePluginManifest, gooseHooksDocument) {
	manifest := goosePluginManifest{
		Name:        "auspex",
		Version:     "0.1.0",
		Description: goosePluginMarker,
	}
	doc := gooseHooksDocument{Hooks: make(map[string][]gooseHookGroup, len(gooseHookEvents))}
	for _, event := range gooseHookEvents {
		doc.Hooks[event.event] = []gooseHookGroup{{
			Matcher: event.matcher,
			Hooks: []gooseHookRef{{
				Type:    "command",
				Command: gooseCommandWithArgs(binary, event.lifecycle, runtimeArgs, enforce && event.event == "PreToolUse"),
				Timeout: event.timeout,
			}},
		}}
	}
	return manifest, doc
}

func readGooseManifest(path string) (goosePluginManifest, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		return goosePluginManifest{}, err
	}
	var manifest goosePluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return goosePluginManifest{}, fmt.Errorf("parse Goose plugin manifest %s: %w", path, err)
	}
	return manifest, nil
}

func readGooseHooks(path string) (gooseHooksDocument, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		return gooseHooksDocument{}, err
	}
	var doc gooseHooksDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return gooseHooksDocument{}, fmt.Errorf("parse Goose hooks %s: %w", path, err)
	}
	return doc, nil
}

func isAuspexGooseManifest(path string) bool {
	manifest, err := readGooseManifest(path)
	return err == nil && isAuspexGooseManifestDocument(manifest)
}

func isAuspexGooseManifestDocument(manifest goosePluginManifest) bool {
	return manifest.Name == "auspex" && manifest.Description == goosePluginMarker
}

func isAuspexGooseHooks(path string) bool {
	doc, err := readGooseHooks(path)
	return err == nil && isAuspexGooseHooksDocument(doc)
}

func isAuspexGooseHooksDocument(doc gooseHooksDocument) bool {
	if len(doc.Hooks) != len(gooseHookEvents) {
		return false
	}
	for _, event := range gooseHookEvents {
		groups := doc.Hooks[event.event]
		if len(groups) != 1 || groups[0].Matcher != event.matcher || len(groups[0].Hooks) != 1 {
			return false
		}
		ref := groups[0].Hooks[0]
		if ref.Type != "command" || ref.Timeout != event.timeout || !isAuspexHookCommand(ref.Command) {
			return false
		}
	}
	return true
}

func readGooseManifestIfExists(path string) (goosePluginManifest, bool, error) {
	manifest, err := readGooseManifest(path)
	if os.IsNotExist(err) {
		return goosePluginManifest{}, false, nil
	}
	if err != nil {
		return goosePluginManifest{}, false, err
	}
	return manifest, true, nil
}

func readGooseHooksIfExists(path string) (gooseHooksDocument, bool, error) {
	doc, err := readGooseHooks(path)
	if os.IsNotExist(err) {
		return gooseHooksDocument{}, false, nil
	}
	if err != nil {
		return gooseHooksDocument{}, false, err
	}
	return doc, true, nil
}

func installGooseWithArgs(root, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentGoose, SettingsPath: root, Supported: true}
	manifestPath, hooksPath := gooseManifestPath(root), gooseHooksPath(root)
	if entries, err := os.ReadDir(root); err == nil {
		_, manifestErr := os.Stat(manifestPath)
		_, hooksErr := os.Stat(hooksPath)
		if os.IsNotExist(manifestErr) && os.IsNotExist(hooksErr) && len(entries) > 0 {
			return rep, fmt.Errorf("refusing to claim non-empty Goose plugin directory without auspex-owned files at %s", root)
		}
	} else if !os.IsNotExist(err) {
		return rep, err
	}
	manifest, manifestExists, err := readGooseManifestIfExists(manifestPath)
	if err != nil {
		return rep, err
	}
	if manifestExists && !isAuspexGooseManifestDocument(manifest) {
		return rep, fmt.Errorf("refusing to overwrite existing non-auspex Goose plugin manifest at %s", manifestPath)
	}
	hooks, hooksExists, err := readGooseHooksIfExists(hooksPath)
	if err != nil {
		return rep, err
	}
	if hooksExists && !isAuspexGooseHooksDocument(hooks) {
		return rep, fmt.Errorf("refusing to overwrite existing non-auspex Goose hooks at %s", hooksPath)
	}
	manifest, hooks = gooseDocuments(binary, runtimeArgs, enforce)
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return rep, err
	}
	hooksData, err := json.MarshalIndent(hooks, "", "  ")
	if err != nil {
		return rep, err
	}
	if err := writeFileAtomic(manifestPath, append(manifestData, '\n')); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(hooksPath, append(hooksData, '\n')); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed auspex Goose Open Plugins hooks"
	if enforce {
		rep.Message += " in enforce mode"
	}
	return rep, nil
}

func uninstallGoose(root string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentGoose, SettingsPath: root, Supported: true}
	manifestPath, hooksPath := gooseManifestPath(root), gooseHooksPath(root)
	manifest, manifestExists, err := readGooseManifestIfExists(manifestPath)
	if err != nil {
		return rep, err
	}
	hooks, hooksExists, err := readGooseHooksIfExists(hooksPath)
	if err != nil {
		return rep, err
	}
	ownedPaths := make([]string, 0, 2)
	if manifestExists && isAuspexGooseManifestDocument(manifest) {
		ownedPaths = append(ownedPaths, manifestPath)
	}
	if hooksExists && isAuspexGooseHooksDocument(hooks) {
		ownedPaths = append(ownedPaths, hooksPath)
	}
	changed := false
	for _, path := range ownedPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return rep, err
		}
		changed = true
	}
	if changed {
		_ = os.Remove(filepath.Join(root, "hooks"))
		_ = os.Remove(root)
		rep.Changed, rep.Message = true, "removed auspex Goose hook plugin files"
	} else {
		rep.Message = "no auspex Goose hook plugin present"
	}
	return rep, nil
}

func statusGoose(root string) InstallReport {
	manifest := isAuspexGooseManifest(gooseManifestPath(root))
	hooks := isAuspexGooseHooks(gooseHooksPath(root))
	rep := InstallReport{Agent: AgentGoose, SettingsPath: root, Supported: true, Installed: manifest && hooks}
	if rep.Installed {
		rep.Message = "auspex Goose hook plugin installed"
	} else if manifest || hooks {
		rep.Message = "partial auspex Goose hook plugin install"
	} else {
		rep.Message = "auspex Goose hook plugin not installed"
	}
	return rep
}

func configReadableGoose(root string) error {
	info, err := os.Stat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: Goose plugin path is not a directory", root)
	}
	for _, path := range []string{gooseManifestPath(root), gooseHooksPath(root)} {
		if _, err := os.Lstat(path); err == nil {
			if strings.HasSuffix(path, gooseManifestFile) {
				_, err = readGooseManifest(path)
			} else {
				_, err = readGooseHooks(path)
			}
			if err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
