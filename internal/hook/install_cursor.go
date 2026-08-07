package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Cursor uses a flat event-to-command schema. Its installer preserves unrelated
// entries and removes only marker-owned auspex commands.

// cursorHookEvent pairs one native Cursor event with its callback deadline and
// optional tool matcher. Cursor's Read and ReadFile actions use the specialized
// beforeReadFile callback because some builds omit the generic callbacks for
// ReadFile. The generic stream excludes those names to avoid duplicate events.
type cursorHookEvent struct {
	event   string
	matcher string
	timeout int
}

// Cursor matchers are JavaScript regular expressions. Read and ReadFile use the
// specialized callback below, so exclude both names from the generic stream.
const cursorNonReadToolMatcher = "^(?!(?:Read|ReadFile)$).*"

var cursorHookEvents = []cursorHookEvent{
	{event: "beforeSubmitPrompt", timeout: promptHookTimeoutSeconds},
	{event: "preToolUse", matcher: cursorNonReadToolMatcher, timeout: fastHookTimeoutSeconds},
	{event: "beforeReadFile", timeout: fastHookTimeoutSeconds},
	{event: "postToolUse", matcher: cursorNonReadToolMatcher, timeout: fastHookTimeoutSeconds},
	{event: "postToolUseFailure", matcher: cursorNonReadToolMatcher, timeout: fastHookTimeoutSeconds},
	{event: "stop", timeout: stopHookTimeoutSeconds},
	{event: "sessionStart", timeout: fastHookTimeoutSeconds},
	{event: "sessionEnd", timeout: fastHookTimeoutSeconds},
	{event: "subagentStart", timeout: fastHookTimeoutSeconds},
	{event: "subagentStop", timeout: fastHookTimeoutSeconds},
}

// cursorHookEntry is one command-hook entry under a Cursor event. Cursor reads
// "command"; unrelated keys a user set on their own entries are preserved via
// the raw-message round-trip in cursorSettings, so this typed shape is only used
// for the entries auspex itself writes and for detecting them.
type cursorHookEntry struct {
	Command string `json:"command"`
	Matcher string `json:"matcher,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

// cursorSettings holds a parsed hooks.json with its hooks block split out for
// editing. Unrelated top-level keys (e.g. "version") are preserved verbatim in
// values, and each event's entry list is kept as raw messages so a user's own
// entries — including any extra keys on them — round-trip untouched.
type cursorSettings struct {
	values map[string]json.RawMessage
	hooks  map[string][]json.RawMessage
}

// cursorCommandWithArgs builds the hook command auspex writes for a Cursor event. It
// passes the event's own name as the positional argument (resolved at runtime by
// ResolveLifecycle) and carries the auspex marker so detection survives a
// renamed binary. Runtime args carry the validated install-time output choices.
func cursorCommandWithArgs(binary, event string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, event, AgentCursor, runtimeArgs, enforce)
}

// readCursorSettings loads a hooks.json, splitting the hooks block out for
// editing. A missing or empty file yields empty settings so install can create
// it.
func readCursorSettings(path string) (cursorSettings, error) {
	cs := cursorSettings{
		values: map[string]json.RawMessage{},
		hooks:  map[string][]json.RawMessage{},
	}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cs, nil
		}
		return cursorSettings{}, err
	}
	if len(data) == 0 {
		return cs, nil
	}
	if err := json.Unmarshal(data, &cs.values); err != nil {
		return cursorSettings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cs.values == nil {
		return cursorSettings{}, fmt.Errorf("parse %s: top-level value must be an object", path)
	}
	if raw, ok := cs.values["version"]; ok {
		var version float64
		if err := json.Unmarshal(raw, &version); err != nil || version != 1 {
			return cursorSettings{}, fmt.Errorf("parse %s: version must be numeric 1", path)
		}
	}
	if raw, ok := cs.values["hooks"]; ok {
		if err := json.Unmarshal(raw, &cs.hooks); err != nil {
			return cursorSettings{}, fmt.Errorf("parse hooks in %s: %w", path, err)
		}
		if cs.hooks == nil {
			return cursorSettings{}, fmt.Errorf("parse hooks in %s: hooks must be an object", path)
		}
	}
	if cs.hooks == nil {
		cs.hooks = map[string][]json.RawMessage{}
	}
	return cs, nil
}

// marshal renders the settings back to indented JSON, folding the edited hooks
// block back in, defaulting "version" to 1 when absent (Cursor requires it), and
// preserving every other top-level key. The hooks block is always emitted, even
// when empty: Cursor's schema is {version,hooks:{...}}, so after an uninstall
// that removed the last entry the file must still carry a (possibly empty) hooks
// map rather than collapsing to a version-only object.
func (cs cursorSettings) marshal() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(cs.values)+2)
	for k, v := range cs.values {
		if k != "hooks" {
			out[k] = v
		}
	}
	if _, ok := out["version"]; !ok {
		out["version"] = json.RawMessage("1")
	}
	hooks := cs.hooks
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

// entryIsAuspex reports whether a raw hook entry is one auspex installed,
// detected by the marker auspex owns and always emits in the command — never by
// the binary's name, so a renamed binary is still recognized.
func entryIsAuspex(raw json.RawMessage) bool {
	// Decode only the owned discriminator. A foreign or externally modified
	// timeout/matcher must not make an otherwise recognizable command impossible
	// to uninstall.
	var e struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return false
	}
	return isAuspexHookCommand(e.Command)
}

// hasAuspexHooks reports whether any auspex-installed hook is present.
func (cs cursorSettings) hasAuspexHooks() bool {
	for _, entries := range cs.hooks {
		for _, raw := range entries {
			if entryIsAuspex(raw) {
				return true
			}
		}
	}
	return false
}

// hasCurrentCursorHooks requires one owned entry at every event in the current
// install contract. This lets status distinguish an older or incomplete install.
func (cs cursorSettings) hasCurrentCursorHooks() bool {
	for _, spec := range cursorHookEvents {
		found := false
		for _, raw := range cs.hooks[spec.event] {
			if entryIsAuspex(raw) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// applyAuspexHooksWithArgs sets auspex's entry for each Cursor event, replacing any prior
// auspex entry so a re-install is idempotent. Non-auspex entries in the same
// event are left untouched and keep their original position.
func (cs cursorSettings) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) error {
	cs.removeAuspexHooks()
	for _, spec := range cursorHookEvents {
		entry, err := json.Marshal(cursorHookEntry{
			Command: cursorCommandWithArgs(binary, spec.event, runtimeArgs, enforce && cursorEnforceEvent(spec.event)),
			Matcher: spec.matcher,
			Timeout: spec.timeout,
		})
		if err != nil {
			return err
		}
		cs.hooks[spec.event] = append(cs.hooks[spec.event], json.RawMessage(entry))
	}
	return nil
}

func cursorEnforceEvent(event string) bool {
	return event == "preToolUse" || event == "beforeReadFile"
}

// removeAuspexHooks strips every auspex-installed entry, dropping now-empty event
// keys, and reports whether anything changed.
func (cs cursorSettings) removeAuspexHooks() bool {
	changed := false
	for event, entries := range cs.hooks {
		kept := make([]json.RawMessage, 0, len(entries))
		for _, raw := range entries {
			if entryIsAuspex(raw) {
				changed = true
				continue
			}
			kept = append(kept, raw)
		}
		if len(kept) == 0 {
			delete(cs.hooks, event)
		} else {
			cs.hooks[event] = kept
		}
	}
	return changed
}

// stripAuspexEntries drops auspex entries from an event's list, so
// applyAuspexHooks never leaves a stale duplicate behind.
func stripAuspexEntries(entries []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(entries))
	for _, raw := range entries {
		if entryIsAuspex(raw) {
			continue
		}
		out = append(out, raw)
	}
	return out
}

// CursorSettingsPath returns the user-level Cursor hooks.json path under home.
// auspex installs to the USER scope by default; project-level paths can be
// targeted explicitly with --settings.
func CursorSettingsPath(home string) string {
	return filepath.Join(home, ".cursor", "hooks.json")
}

// installCursorWithArgs wires auspex's hook entries into a Cursor hooks.json. It is
// idempotent and backs the pristine file up before the first write.
func installCursorWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installCursorAt(path, binary, runtimeArgs, false, enforce)
}

func installCursorManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installCursorAt(path, binary, runtimeArgs, true, enforce)
}

func installCursorAt(path, binary string, runtimeArgs []string, managed, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCursor, SettingsPath: path, Supported: true}
	cs, err := readCursorSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := cs.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce); err != nil {
		return rep, err
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

// uninstallCursor removes only auspex's entries from a Cursor hooks.json,
// leaving every other key and entry intact. A missing file or absent auspex
// entries is a no-op (Changed=false).
func uninstallCursor(path string) (InstallReport, error) {
	return uninstallCursorAt(path, false)
}

func uninstallCursorManaged(path string) (InstallReport, error) {
	return uninstallCursorAt(path, true)
}

func uninstallCursorAt(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCursor, SettingsPath: path, Supported: true}
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

// statusCursor reports whether auspex hooks are present in a Cursor hooks.json,
// without modifying anything.
func statusCursor(path string) InstallReport {
	rep := InstallReport{Agent: AgentCursor, SettingsPath: path, Supported: true}
	cs, err := readCursorSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = cs.hasCurrentCursorHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else if cs.hasAuspexHooks() {
		rep.Message = "auspex hooks incomplete; reinstall to update the event set"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}
