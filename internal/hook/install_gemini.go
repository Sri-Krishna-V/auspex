package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// install_gemini.go wires auspex into Gemini CLI's settings.json hook block.
// Gemini uses the same event -> matcher groups shape as Claude/Codex, but each
// command hook also has a structured name; auspex owns name:"auspex" as the
// idempotency marker. Installs preserve unrelated settings and remove only
// auspex entries on uninstall.

// geminiHookEvent is a Gemini settings.json event name paired with the auspex
// lifecycle argument its command invokes and an optional matcher.
type geminiHookEvent struct {
	// settingsKey is the key under "hooks" in Gemini's settings.json. For TOOL
	// events (BeforeTool/AfterTool) Gemini uses a REGEX matcher; for LIFECYCLE
	// events (SessionStart/SessionEnd) it uses an EXACT-STRING matcher.
	settingsKey string
	// lifecycle is the positional argument passed to `auspex hook <lifecycle>`.
	lifecycle string
	// matcher restricts which events fire the hook; empty means all. For tool
	// events an empty matcher (all tools) is used because auspex observes the whole
	// narrow tool vocabulary it classifies on.
	matcher string
	// timeout is the hook's timeout in milliseconds; 0 omits it. Gemini timeouts are
	// in MILLISECONDS (distinct from Claude/Codex, whose timeouts are seconds).
	timeoutMs int
}

// geminiHookEvents covers prompts, tool execution, assistant-turn completion,
// and session boundaries. Model/chunk hooks are intentionally not installed.
var geminiHookEvents = []geminiHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", matcher: "SessionStart", timeoutMs: 5000},
	{settingsKey: "BeforeAgent", lifecycle: "prompt-submit", matcher: "*", timeoutMs: 5000},
	{settingsKey: "BeforeTool", lifecycle: "gemini-pre-tool", matcher: "", timeoutMs: 5000},
	{settingsKey: "AfterTool", lifecycle: "gemini-post-tool", matcher: "", timeoutMs: 5000},
	{settingsKey: "AfterAgent", lifecycle: "assistant", matcher: "*", timeoutMs: 5000},
	{settingsKey: "SessionEnd", lifecycle: "session-end", matcher: "SessionEnd", timeoutMs: 5000},
}

// geminiHookName is the value auspex writes into each hook entry's "name" field.
// auspex uses it as the stable ownership marker for status and uninstall.
const geminiHookName = "auspex"

// geminiHookRef is one command-hook entry in a Gemini settings hook group.
type geminiHookRef struct {
	Name        string
	Type        string
	Command     string
	Timeout     int
	Description string
	fields      map[string]json.RawMessage
}

// geminiHookGroup is a matcher plus the command hooks that fire for it.
type geminiHookGroup struct {
	Matcher string
	Hooks   []geminiHookRef
	fields  map[string]json.RawMessage
}

func (h *geminiHookRef) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Command     string `json:"command"`
		Timeout     int    `json:"timeout"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &h.fields); err != nil {
		return err
	}
	h.Name, h.Type, h.Command = wire.Name, wire.Type, wire.Command
	h.Timeout, h.Description = wire.Timeout, wire.Description
	return nil
}

func (h geminiHookRef) MarshalJSON() ([]byte, error) {
	out := cloneRawFields(h.fields)
	if h.Name != "" {
		if err := setJSONField(out, "name", h.Name); err != nil {
			return nil, err
		}
	}
	if h.Type != "" {
		if err := setJSONField(out, "type", h.Type); err != nil {
			return nil, err
		}
	}
	if h.Command != "" {
		if err := setJSONField(out, "command", h.Command); err != nil {
			return nil, err
		}
	}
	if h.Timeout != 0 {
		if err := setJSONField(out, "timeout", h.Timeout); err != nil {
			return nil, err
		}
	}
	if h.Description != "" {
		if err := setJSONField(out, "description", h.Description); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}

func (g *geminiHookGroup) UnmarshalJSON(data []byte) error {
	var wire struct {
		Matcher string          `json:"matcher"`
		Hooks   []geminiHookRef `json:"hooks"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &g.fields); err != nil {
		return err
	}
	g.Matcher, g.Hooks = wire.Matcher, wire.Hooks
	return nil
}

func (g geminiHookGroup) MarshalJSON() ([]byte, error) {
	out := cloneRawFields(g.fields)
	if g.Matcher != "" {
		if err := setJSONField(out, "matcher", g.Matcher); err != nil {
			return nil, err
		}
	}
	if err := setJSONField(out, "hooks", g.Hooks); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// geminiSettings holds a Gemini settings.json with its "hooks" block split out for
// editing. Unrelated top-level keys are preserved verbatim so a round-trip never
// drops a user's configuration.
type geminiSettings struct {
	values map[string]json.RawMessage
	hooks  map[string][]geminiHookGroup
}

// isAuspexGeminiHook reports whether a Gemini hook entry was installed by auspex,
// detected by the structured "name" marker auspex owns — never by the binary's
// path, so a renamed binary is still recognized. It also accepts the shared
// --installed-by marker if a future Gemini build strips the name field.
func isAuspexGeminiHook(h geminiHookRef) bool {
	return h.Name == geminiHookName || isAuspexHookCommand(h.Command)
}

// GeminiSettingsPath returns the user-level Gemini settings.json path.
func GeminiSettingsPath(home string) string {
	return filepath.Join(geminiConfigRoot(home), "settings.json")
}

func geminiConfigRoot(home string) string {
	if override := os.Getenv("GEMINI_CLI_HOME"); override != "" {
		home = override
	}
	return filepath.Join(home, ".gemini")
}

// geminiCommandWithArgs builds the hook command auspex writes for a Gemini
// event. The command carries the auspex marker so detection survives a renamed
// binary even if the structured name field is ever lost.
func geminiCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentGemini, runtimeArgs, enforce)
}

// readGeminiSettings loads a Gemini settings.json, splitting the "hooks" block out
// for editing. A missing file is not an error: it yields an empty settings value so
// install can create it.
func readGeminiSettings(path string) (geminiSettings, error) {
	gs := geminiSettings{
		values: map[string]json.RawMessage{},
		hooks:  map[string][]geminiHookGroup{},
	}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return gs, nil
		}
		return geminiSettings{}, err
	}
	if len(data) == 0 {
		return gs, nil
	}
	if err := json.Unmarshal(data, &gs.values); err != nil {
		return geminiSettings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if raw, ok := gs.values["hooks"]; ok {
		if err := json.Unmarshal(raw, &gs.hooks); err != nil {
			return geminiSettings{}, fmt.Errorf("parse hooks in %s: %w", path, err)
		}
	}
	if gs.hooks == nil {
		gs.hooks = map[string][]geminiHookGroup{}
	}
	return gs, nil
}

// marshal renders the Gemini settings back to indented JSON, folding the edited
// hooks block back in and preserving every other top-level key. Like Codex's
// marshalAlwaysHooks it always emits the hooks map (even when empty) so an
// uninstall that removed the last entry leaves a valid {hooks:{}} schema rather
// than collapsing to an object with no hooks key.
func (gs geminiSettings) marshal() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(gs.values)+1)
	for k, v := range gs.values {
		if k != "hooks" {
			out[k] = v
		}
	}
	hooks := gs.hooks
	if hooks == nil {
		hooks = map[string][]geminiHookGroup{}
	}
	data, err := json.Marshal(hooks)
	if err != nil {
		return nil, err
	}
	out["hooks"] = data
	return json.MarshalIndent(out, "", "  ")
}

// hasAuspexHooks reports whether any auspex-installed Gemini hook is present.
func (gs geminiSettings) hasAuspexHooks() bool {
	for _, groups := range gs.hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isAuspexGeminiHook(h) {
					return true
				}
			}
		}
	}
	return false
}

// stripAuspexGeminiGroups drops groups that consist solely of auspex hooks and
// removes auspex hooks from mixed groups, so applyAuspexHooks never leaves a stale
// duplicate behind and a user's own hooks in the same event are preserved.
func stripAuspexGeminiGroups(groups []geminiHookGroup) []geminiHookGroup {
	out := make([]geminiHookGroup, 0, len(groups))
	for _, g := range groups {
		filtered := g.Hooks[:0:0]
		for _, h := range g.Hooks {
			if isAuspexGeminiHook(h) {
				continue
			}
			filtered = append(filtered, h)
		}
		if len(filtered) == 0 {
			continue
		}
		g.Hooks = filtered
		out = append(out, g)
	}
	return out
}

// applyAuspexHooksWithArgs sets auspex's hook entries for each wired Gemini event,
// stripping any prior auspex group first so a re-install stays idempotent and
// never duplicates. Non-auspex groups in the same event are left untouched.
func (gs geminiSettings) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	for _, ev := range geminiHookEvents {
		groups := stripAuspexGeminiGroups(gs.hooks[ev.settingsKey])
		groups = append(groups, geminiHookGroup{
			Matcher: ev.matcher,
			Hooks: []geminiHookRef{{
				Name:        geminiHookName,
				Type:        "command",
				Command:     geminiCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.settingsKey == "BeforeTool"),
				Timeout:     ev.timeoutMs,
				Description: "auspex endpoint activity monitor",
			}},
		})
		gs.hooks[ev.settingsKey] = groups
	}
}

// removeAuspexHooks strips every auspex-installed hook, dropping now-empty groups
// and now-empty event keys, and reports whether anything changed.
func (gs geminiSettings) removeAuspexHooks() bool {
	changed := false
	for key, groups := range gs.hooks {
		kept := make([]geminiHookGroup, 0, len(groups))
		for _, g := range groups {
			filtered := g.Hooks[:0:0]
			for _, h := range g.Hooks {
				if isAuspexGeminiHook(h) {
					changed = true
					continue
				}
				filtered = append(filtered, h)
			}
			if len(filtered) == 0 {
				continue
			}
			g.Hooks = filtered
			kept = append(kept, g)
		}
		if len(kept) == 0 {
			delete(gs.hooks, key)
		} else {
			gs.hooks[key] = kept
		}
	}
	return changed
}

// installGeminiWithArgs wires auspex into a Gemini settings file.
func installGeminiWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installGeminiAt(path, binary, runtimeArgs, false, enforce)
}

func installGeminiManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installGeminiAt(path, binary, runtimeArgs, true, enforce)
}

func installGeminiAt(path, binary string, runtimeArgs []string, managed, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentGemini, SettingsPath: path, Supported: true}
	gs, err := readGeminiSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	gs.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeGeminiSettings(path, gs, managed); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = installMessage(enforce)
	if managed {
		rep.Message = "installed auspex managed hooks"
		if enforce {
			rep.Message += " (enforce mode: blocks matches from rules marked enforce=true)"
		}
	}
	return rep, nil
}

// uninstallGemini removes only auspex's entries from a Gemini settings.json,
// leaving every other key and group intact and a valid schema behind. A missing
// file or absent auspex entries is a no-op (Changed=false).
func uninstallGemini(path string) (InstallReport, error) {
	return uninstallGeminiAt(path, false)
}

func uninstallGeminiManaged(path string) (InstallReport, error) {
	return uninstallGeminiAt(path, true)
}

func uninstallGeminiAt(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentGemini, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	gs, err := readGeminiSettings(path)
	if err != nil {
		return rep, err
	}
	if !gs.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeGeminiSettings(path, gs, managed); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	if managed {
		rep.Message = "removed auspex managed hooks"
	}
	return rep, nil
}

// statusGemini reports whether auspex hooks are present in a Gemini settings.json,
// without modifying anything.
func statusGemini(path string) InstallReport {
	rep := InstallReport{Agent: AgentGemini, SettingsPath: path, Supported: true}
	gs, err := readGeminiSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = gs.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

// writeGeminiSettings renders and atomically writes a Gemini settings.json. It
// shares writeFileAtomic for identical durability and 0600 permission guarantees
// (a settings file can carry tokens).
func writeGeminiSettings(path string, gs geminiSettings, managed bool) error {
	data, err := gs.marshal()
	if err != nil {
		return err
	}
	return writeHookConfig(path, data, managed)
}
