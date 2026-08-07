package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// install_windsurf.go wires auspex into Windsurf's lifecycle-hook settings.
// Windsurf's hooks.json schema differs from both Claude's settings.json and
// Cursor's hooks.json: there is no top-level "version", and each event maps to a
// list of entry objects carrying {command, show_output, working_directory}
// rather than Cursor's bare {command}. The installer preserves unrelated keys
// and removes only auspex-owned entries.

// windsurfHookEvents is the closed set of Windsurf lifecycle events auspex wires,
// matching the observed in-prod set. auspex passes each event's own name as the
// positional argument; the live handler resolves it via ResolveLifecycle
// (case-insensitive substring match on the action verb), robust to minor naming
// drift across Windsurf builds.
var windsurfHookEvents = []string{
	"pre_user_prompt",
	"pre_read_code",
	"post_read_code",
	"pre_write_code",
	"post_write_code",
	"pre_run_command",
	"post_run_command",
	"pre_mcp_tool_use",
	"post_mcp_tool_use",
	"post_cascade_response",
}

// windsurfHookEntry is one command-hook entry under a Windsurf event, matching
// the verified Windsurf shape {command, show_output, working_directory}. Windsurf
// reads "command" and the two control fields; show_output is always false so
// routine hook output never surfaces in the agent UI, and
// working_directory is the relative "." (see windsurfWorkingDir) so the hook runs
// from Windsurf's active-workspace directory — a user-scope install has no single
// fixed workspace to pin. Unrelated keys a user set on their own entries
// round-trip via the raw-message handling in windsurfSettings, so this typed
// shape is only used for auspex's own entries and for detecting them.
type windsurfHookEntry struct {
	Command          string `json:"command"`
	ShowOutput       bool   `json:"show_output"`
	WorkingDirectory string `json:"working_directory"`
}

// windsurfWorkingDir is the working_directory auspex writes on its own entries.
// A user-scope install (~/.codeium/windsurf/hooks.json) has no single fixed
// workspace, so "." lets Windsurf run the hook from whatever workspace is active
// at fire time — the same directory the observed action runs in.
const windsurfWorkingDir = "."

// windsurfSettings holds a parsed hooks.json with its hooks block split out for
// editing. Unrelated top-level keys are preserved verbatim in values, and each
// event's entry list is kept as raw messages so a user's own entries — including
// any extra keys on them — round-trip untouched.
type windsurfSettings struct {
	values map[string]json.RawMessage
	hooks  map[string][]json.RawMessage
}

// windsurfCommandWithArgs builds the hook command auspex writes for a Windsurf event. It
// passes the event's own name as the positional argument (resolved at runtime by
// ResolveLifecycle) and carries the auspex marker so detection survives a renamed
// binary. Runtime args carry the validated install-time output choices.
func windsurfCommandWithArgs(binary, event string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, event, AgentWindsurf, runtimeArgs, enforce)
}

// readWindsurfSettings loads a hooks.json, splitting the hooks block out for
// editing. A missing or empty file yields empty settings so install can create
// it.
func readWindsurfSettings(path string) (windsurfSettings, error) {
	ws := windsurfSettings{
		values: map[string]json.RawMessage{},
		hooks:  map[string][]json.RawMessage{},
	}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ws, nil
		}
		return windsurfSettings{}, err
	}
	if len(data) == 0 {
		return ws, nil
	}
	if err := json.Unmarshal(data, &ws.values); err != nil {
		return windsurfSettings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if raw, ok := ws.values["hooks"]; ok {
		if err := json.Unmarshal(raw, &ws.hooks); err != nil {
			return windsurfSettings{}, fmt.Errorf("parse hooks in %s: %w", path, err)
		}
	}
	if ws.hooks == nil {
		ws.hooks = map[string][]json.RawMessage{}
	}
	return ws, nil
}

// marshal renders the settings back to indented JSON, folding the edited hooks
// block back in and preserving every other top-level key. The hooks block is
// always emitted, even when empty: Windsurf's schema is {hooks:{...}}, so after
// an uninstall that removed the last entry the file must still carry a (possibly
// empty) hooks map rather than collapsing to an object with no hooks key.
func (ws windsurfSettings) marshal() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(ws.values)+1)
	for k, v := range ws.values {
		if k != "hooks" {
			out[k] = v
		}
	}
	hooks := ws.hooks
	if hooks == nil {
		hooks = map[string][]json.RawMessage{}
	}
	data, err := json.Marshal(hooks)
	if err != nil {
		return nil, err
	}
	out["hooks"] = data
	return json.MarshalIndent(out, "", "  ")
}

// windsurfEntryIsAuspex reports whether a raw hook entry is one auspex installed,
// detected by the marker auspex owns and always emits in the command — never by
// the binary's name, so a renamed binary is still recognized.
func windsurfEntryIsAuspex(raw json.RawMessage) bool {
	var e windsurfHookEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return false
	}
	return isAuspexHookCommand(e.Command)
}

// hasAuspexHooks reports whether any auspex-installed hook is present.
func (ws windsurfSettings) hasAuspexHooks() bool {
	for _, entries := range ws.hooks {
		for _, raw := range entries {
			if windsurfEntryIsAuspex(raw) {
				return true
			}
		}
	}
	return false
}

// applyAuspexHooksWithArgs sets auspex's entry for each Windsurf event, replacing any
// prior auspex entry so a re-install is idempotent. Non-auspex entries in the
// same event are left untouched and keep their original position.
func (ws windsurfSettings) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) error {
	for _, event := range windsurfHookEvents {
		kept := stripWindsurfAuspexEntries(ws.hooks[event])
		entry, err := json.Marshal(windsurfHookEntry{
			Command:          windsurfCommandWithArgs(binary, event, runtimeArgs, enforce && windsurfEnforceEvent(event)),
			ShowOutput:       false,
			WorkingDirectory: windsurfWorkingDir,
		})
		if err != nil {
			return err
		}
		ws.hooks[event] = append(kept, json.RawMessage(entry))
	}
	return nil
}

func windsurfEnforceEvent(event string) bool {
	switch event {
	case "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use":
		return true
	default:
		return false
	}
}

// removeAuspexHooks strips every auspex-installed entry, dropping now-empty event
// keys, and reports whether anything changed.
func (ws windsurfSettings) removeAuspexHooks() bool {
	changed := false
	for event, entries := range ws.hooks {
		kept := make([]json.RawMessage, 0, len(entries))
		for _, raw := range entries {
			if windsurfEntryIsAuspex(raw) {
				changed = true
				continue
			}
			kept = append(kept, raw)
		}
		if len(kept) == 0 {
			delete(ws.hooks, event)
		} else {
			ws.hooks[event] = kept
		}
	}
	return changed
}

// stripWindsurfAuspexEntries drops auspex entries from an event's list, so
// applyAuspexHooks never leaves a stale duplicate behind.
func stripWindsurfAuspexEntries(entries []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(entries))
	for _, raw := range entries {
		if windsurfEntryIsAuspex(raw) {
			continue
		}
		out = append(out, raw)
	}
	return out
}

// WindsurfSettingsPath returns the Devin Desktop IDE user-level Windsurf/Cascade
// hooks.json path under home. auspex installs to the USER scope by default;
// Windsurf/Cascade also reads workspace (.windsurf/hooks.json) and system
// (/etc/windsurf/hooks.json on Linux/WSL, plus platform equivalents) hook files,
// which can be targeted explicitly with --settings.
func WindsurfSettingsPath(home string) string {
	return filepath.Join(home, ".codeium", "windsurf", "hooks.json")
}

// installWindsurfWithArgs wires auspex's hook entries into a Windsurf hooks.json. It is
// idempotent and backs the pristine file up before the first write.
func installWindsurfWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installWindsurfAt(path, binary, runtimeArgs, false, enforce)
}

func installWindsurfManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installWindsurfAt(path, binary, runtimeArgs, true, enforce)
}

func installWindsurfAt(path, binary string, runtimeArgs []string, managed, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentWindsurf, SettingsPath: path, Supported: true}
	ws, err := readWindsurfSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := ws.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce); err != nil {
		return rep, err
	}
	data, err := ws.marshal()
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

// uninstallWindsurf removes only auspex's entries from a Windsurf hooks.json,
// leaving every other key and entry intact. A missing file or absent auspex
// entries is a no-op (Changed=false).
func uninstallWindsurf(path string) (InstallReport, error) {
	return uninstallWindsurfAt(path, false)
}

func uninstallWindsurfManaged(path string) (InstallReport, error) {
	return uninstallWindsurfAt(path, true)
}

func uninstallWindsurfAt(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentWindsurf, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	ws, err := readWindsurfSettings(path)
	if err != nil {
		return rep, err
	}
	if !ws.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	data, err := ws.marshal()
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

// statusWindsurf reports whether auspex hooks are present in a Windsurf
// hooks.json, without modifying anything.
func statusWindsurf(path string) InstallReport {
	rep := InstallReport{Agent: AgentWindsurf, SettingsPath: path, Supported: true}
	ws, err := readWindsurfSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = ws.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}
