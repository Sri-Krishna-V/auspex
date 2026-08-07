package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Factory hook groups are Claude-shaped, but its standalone hooks.json uses a
// top-level event map while settings.json nests that map under "hooks".

// factoryHookEvents covers the action and true session-boundary events that map
// cleanly to auspex's event vocabulary.
var factoryHookEvents = []claudeHookEvent{
	{settingsKey: "SessionStart", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{settingsKey: "UserPromptSubmit", lifecycle: string(LifecyclePromptSubmit), timeout: promptHookTimeoutSeconds},
	{settingsKey: "PreToolUse", lifecycle: string(LifecycleFactoryPreTool), timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUse", lifecycle: string(LifecycleFactoryPostTool), timeout: fastHookTimeoutSeconds},
	{settingsKey: "Stop", lifecycle: string(LifecycleAssistant), timeout: stopHookTimeoutSeconds},
	{settingsKey: "SubagentStop", lifecycle: string(LifecycleSessionEnd), timeout: stopHookTimeoutSeconds},
	{settingsKey: "SessionEnd", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
}

// factoryCommandWithArgs builds the hook command auspex writes for a Factory event. It
// passes the auspex lifecycle as the positional argument (the live handler reads it
// via ResolveLifecycle, which for Factory resolves through resolveFactoryEvent) and
// carries the auspex marker so detection survives a renamed binary and stamps
// --agent factory so events carry AgentFactory.
func factoryCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentFactory, runtimeArgs, enforce)
}

// applyFactoryHooksWithArgs sets auspex's hook entries for each Factory lifecycle event,
// replacing any prior auspex entry so a re-install is idempotent. Non-auspex hooks
// in the same event are left untouched. It is the Factory twin of
// settingsFile.applyAuspexHooksWithArgs, differing only in the event list and the
// --agent factory command.
func (sf settingsFile) applyFactoryHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	for _, ev := range factoryHookEvents {
		groups := stripAuspexGroups(sf.hooks[ev.settingsKey])
		groups = append(groups, hookGroup{
			Matcher: ev.matcher,
			Hooks: []hookRef{{
				Type:    "command",
				Command: factoryCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.settingsKey == "PreToolUse"),
				Timeout: ev.timeout,
			}},
		})
		sf.hooks[ev.settingsKey] = groups
	}
}

// FactorySettingsPath returns Factory's current user-level standalone hook file.
// The installer also migrates Factory's older hooks/hooks.json location and its
// nested settings.json hook source without dropping foreign entries.
func FactorySettingsPath(home string) string {
	return filepath.Join(home, ".factory", "hooks.json")
}

// factoryKnownHookEvents is the complete event-key set accepted by Factory's
// standalone hooks.json schema. Auspex wires the subset in factoryHookEvents,
// but parses the whole set so status and uninstall can find older owned entries.
var factoryKnownHookEvents = []string{
	"PreToolUse",
	"PostToolUse",
	"Notification",
	"UserPromptSubmit",
	"Stop",
	"SubagentStop",
	"PreCompact",
	"SessionStart",
	"SessionEnd",
}

// factoryHooksFile models Factory's standalone hooks.json wire format: event
// arrays live directly at the top level. This deliberately differs from the
// nested {"hooks": {...}} compatibility block in settings.json.
type factoryHooksFile struct {
	values map[string]json.RawMessage
	hooks  map[string][]hookGroup
	dirty  map[string]bool
}

func newFactoryHooksFile() factoryHooksFile {
	return factoryHooksFile{
		values: map[string]json.RawMessage{},
		hooks:  map[string][]hookGroup{},
		dirty:  map[string]bool{},
	}
}

func decodeFactoryString(raw json.RawMessage, field, path string) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("parse %s in %s: %w", field, path, err)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("parse %s in %s: expected a string", field, path)
	}
	return text, nil
}

func validateFactoryNumber(raw json.RawMessage, field, path string) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("parse %s in %s: %w", field, path, err)
	}
	number, ok := value.(json.Number)
	if !ok {
		return fmt.Errorf("parse %s in %s: expected a number", field, path)
	}
	if _, err := number.Float64(); err != nil {
		return fmt.Errorf("parse %s in %s: invalid number: %w", field, path, err)
	}
	return nil
}

// decodeFactoryHookGroups follows Factory's signed CLI schema rather than the
// more permissive shared Claude codec. Unknown object fields remain preserved,
// matching Zod's default object behavior, while every known field is validated.
func decodeFactoryHookGroups(raw json.RawMessage, event, path string) ([]hookGroup, error) {
	var groupRaws []json.RawMessage
	if err := json.Unmarshal(raw, &groupRaws); err != nil || groupRaws == nil {
		if err == nil {
			err = fmt.Errorf("expected an array")
		}
		return nil, fmt.Errorf("parse %s in %s: %w", event, path, err)
	}
	groups := make([]hookGroup, 0, len(groupRaws))
	for groupIndex, groupRaw := range groupRaws {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(groupRaw, &fields); err != nil || fields == nil {
			if err == nil {
				err = fmt.Errorf("expected an object")
			}
			return nil, fmt.Errorf("parse %s[%d] in %s: %w", event, groupIndex, path, err)
		}
		group := hookGroup{fields: fields}
		if matcher, ok := fields["matcher"]; ok {
			value, err := decodeFactoryString(matcher, fmt.Sprintf("%s[%d].matcher", event, groupIndex), path)
			if err != nil {
				return nil, err
			}
			group.Matcher = value
		}
		if commandRegex, ok := fields["commandRegex"]; ok {
			if _, err := decodeFactoryString(commandRegex, fmt.Sprintf("%s[%d].commandRegex", event, groupIndex), path); err != nil {
				return nil, err
			}
		}
		hooksRaw, ok := fields["hooks"]
		if !ok {
			return nil, fmt.Errorf("parse %s[%d] in %s: required field hooks is missing", event, groupIndex, path)
		}
		var refRaws []json.RawMessage
		if err := json.Unmarshal(hooksRaw, &refRaws); err != nil || refRaws == nil {
			if err == nil {
				err = fmt.Errorf("expected an array")
			}
			return nil, fmt.Errorf("parse %s[%d].hooks in %s: %w", event, groupIndex, path, err)
		}
		group.Hooks = make([]hookRef, 0, len(refRaws))
		for refIndex, refRaw := range refRaws {
			var refFields map[string]json.RawMessage
			if err := json.Unmarshal(refRaw, &refFields); err != nil || refFields == nil {
				if err == nil {
					err = fmt.Errorf("expected an object")
				}
				return nil, fmt.Errorf("parse %s[%d].hooks[%d] in %s: %w", event, groupIndex, refIndex, path, err)
			}
			typeRaw, ok := refFields["type"]
			if !ok {
				return nil, fmt.Errorf("parse %s[%d].hooks[%d] in %s: required field type is missing", event, groupIndex, refIndex, path)
			}
			typeValue, err := decodeFactoryString(typeRaw, fmt.Sprintf("%s[%d].hooks[%d].type", event, groupIndex, refIndex), path)
			if err != nil {
				return nil, err
			}
			if typeValue != "command" {
				return nil, fmt.Errorf("parse %s[%d].hooks[%d].type in %s: expected %q", event, groupIndex, refIndex, path, "command")
			}
			commandRaw, ok := refFields["command"]
			if !ok {
				return nil, fmt.Errorf("parse %s[%d].hooks[%d] in %s: required field command is missing", event, groupIndex, refIndex, path)
			}
			command, err := decodeFactoryString(commandRaw, fmt.Sprintf("%s[%d].hooks[%d].command", event, groupIndex, refIndex), path)
			if err != nil {
				return nil, err
			}
			if timeout, ok := refFields["timeout"]; ok {
				if err := validateFactoryNumber(timeout, fmt.Sprintf("%s[%d].hooks[%d].timeout", event, groupIndex, refIndex), path); err != nil {
					return nil, err
				}
			}
			// Keep timeout in the raw field map so any valid fractional value is
			// round-tripped exactly; auspex's own new refs use integer Timeout.
			group.Hooks = append(group.Hooks, hookRef{
				Type:    typeValue,
				Command: command,
				fields:  refFields,
			})
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func parseFactoryHooks(data []byte, path string) (factoryHooksFile, error) {
	ff := newFactoryHooksFile()
	if len(data) == 0 {
		return factoryHooksFile{}, fmt.Errorf("parse %s: expected a JSON object", path)
	}
	// Factory loads both hooks.json and settings.json with a JSONC parser. Match
	// that signed-client behavior for comments and trailing commas before using
	// the strict schema checks below. Writes intentionally follow the repository's
	// established JSON config-editor behavior: foreign values are preserved, while
	// formatting and comments are canonicalized (the pristine backup retains the
	// original bytes).
	cleaned, err := stripJSONComments(data)
	if err != nil {
		return factoryHooksFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	data = cleaned
	if err := json.Unmarshal(data, &ff.values); err != nil {
		return factoryHooksFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if ff.values == nil {
		return factoryHooksFile{}, fmt.Errorf("parse %s: expected a JSON object", path)
	}
	for _, event := range factoryKnownHookEvents {
		raw, ok := ff.values[event]
		if !ok {
			continue
		}
		groups, err := decodeFactoryHookGroups(raw, event, path)
		if err != nil {
			return factoryHooksFile{}, err
		}
		ff.hooks[event] = groups
	}
	for _, flag := range []string{"hooksDisabled", "showHookOutput"} {
		raw, ok := ff.values[flag]
		if !ok {
			continue
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return factoryHooksFile{}, fmt.Errorf("parse %s in %s: %w", flag, path, err)
		}
		if _, ok := value.(bool); !ok {
			return factoryHooksFile{}, fmt.Errorf("parse %s in %s: expected a boolean", flag, path)
		}
	}
	return ff, nil
}

func readFactoryHooksFile(path string) (factoryHooksFile, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newFactoryHooksFile(), nil
		}
		return factoryHooksFile{}, err
	}
	return parseFactoryHooks(data, path)
}

func (ff factoryHooksFile) boolSetting(name string) (bool, bool) {
	raw, ok := ff.values[name]
	if !ok {
		return false, false
	}
	var value bool
	// readFactoryHooksFile has already validated the type.
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, false
	}
	return value, true
}

func (ff factoryHooksFile) marshal() ([]byte, error) {
	out := cloneRawFields(ff.values)
	for event := range ff.dirty {
		groups, ok := ff.hooks[event]
		if !ok || len(groups) == 0 {
			delete(out, event)
			continue
		}
		if err := setJSONField(out, event, groups); err != nil {
			return nil, err
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

func writeFactoryHooksFile(path string, ff factoryHooksFile) error {
	data, err := ff.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// factorySettingsFile keeps Factory's nested settings.json hook object on the
// same exact schema as a standalone hooks.json while preserving unrelated
// settings fields byte-for-byte at the JSON-value level.
type factorySettingsFile struct {
	values map[string]json.RawMessage
	hooks  factoryHooksFile
}

func newFactorySettingsFile() factorySettingsFile {
	return factorySettingsFile{
		values: map[string]json.RawMessage{},
		hooks:  newFactoryHooksFile(),
	}
}

func readFactorySettings(path string) (factorySettingsFile, error) {
	sf := newFactorySettingsFile()
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sf, nil
		}
		return factorySettingsFile{}, err
	}
	if len(data) == 0 {
		return factorySettingsFile{}, fmt.Errorf("parse %s: expected a JSON object", path)
	}
	data, err = stripJSONComments(data)
	if err != nil {
		return factorySettingsFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &sf.values); err != nil {
		return factorySettingsFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if sf.values == nil {
		return factorySettingsFile{}, fmt.Errorf("parse %s: expected a JSON object", path)
	}
	if raw, ok := sf.values["hooks"]; ok {
		sf.hooks, err = parseFactoryHooks(raw, path+" hooks")
		if err != nil {
			return factorySettingsFile{}, err
		}
	}
	return sf, nil
}

func writeFactorySettings(path string, sf factorySettingsFile) error {
	out := cloneRawFields(sf.values)
	hooksData, err := sf.hooks.marshal()
	if err != nil {
		return err
	}
	if string(hooksData) == "{}" {
		delete(out, "hooks")
	} else {
		out["hooks"] = hooksData
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func (sf factorySettingsFile) hasAuspexHooks() bool {
	return sf.hooks.hasAuspexHooks()
}

func (sf factorySettingsFile) removeAuspexHooks() bool {
	return sf.hooks.removeAuspexHooks()
}

func (sf factorySettingsFile) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	sf.hooks.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
}

func (ff factoryHooksFile) hasEvent(event string) bool {
	_, ok := ff.values[event]
	if ok {
		return true
	}
	_, ok = ff.hooks[event]
	return ok
}

func (ff factoryHooksFile) hasAuspexHooks() bool {
	return settingsFile{hooks: ff.hooks}.hasAuspexHooks()
}

func (ff factoryHooksFile) removeAuspexHooks() bool {
	changed := false
	for event, groups := range ff.hooks {
		if !hasAuspexGroup(groups) {
			continue
		}
		kept := stripAuspexGroups(groups)
		changed = true
		ff.dirty[event] = true
		if len(kept) == 0 {
			delete(ff.hooks, event)
		} else {
			ff.hooks[event] = kept
		}
	}
	return changed
}

func (ff factoryHooksFile) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	settingsFile{hooks: ff.hooks}.applyFactoryHooksWithArgs(binary, runtimeArgs, enforce)
	for _, event := range factoryHookEvents {
		ff.dirty[event.settingsKey] = true
	}
}

func factoryHooksPathForOS(path, goos string) bool {
	base := filepath.Base(path)
	if goos == "windows" {
		return strings.EqualFold(base, "hooks.json")
	}
	return base == "hooks.json"
}

func factoryHooksPath(path string) bool {
	return factoryHooksPathForOS(path, runtime.GOOS)
}

type factoryScopePathKind uint8

const (
	factoryPathOutsideScope factoryScopePathKind = iota
	factoryPathRootHooks
	factoryPathLegacyHooks
	factoryPathSettings
	factoryPathLocalSettings
)

func factoryPathNameEqual(name, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, want)
	}
	return name == want
}

// factoryScopePath identifies the three hook sources within one .factory
// folder. Explicit staging paths outside such a folder remain exact targets.
func factoryScopePath(path string) (factoryScopePathKind, string, string, string) {
	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	base := filepath.Base(clean)

	var root string
	switch {
	case factoryPathNameEqual(base, "hooks.json") && factoryPathNameEqual(filepath.Base(dir), ".factory"):
		root = clean
	case factoryPathNameEqual(base, "hooks.json") &&
		factoryPathNameEqual(filepath.Base(dir), "hooks") &&
		factoryPathNameEqual(filepath.Base(filepath.Dir(dir)), ".factory"):
		root = filepath.Join(filepath.Dir(dir), "hooks.json")
	case factoryPathNameEqual(base, "settings.json") && factoryPathNameEqual(filepath.Base(dir), ".factory"):
		root = filepath.Join(dir, "hooks.json")
	case factoryPathNameEqual(base, "settings.local.json") && factoryPathNameEqual(filepath.Base(dir), ".factory"):
		root = filepath.Join(dir, "hooks.json")
	default:
		return factoryPathOutsideScope, "", "", ""
	}

	factoryDir := filepath.Dir(root)
	legacy := filepath.Join(factoryDir, "hooks", "hooks.json")
	settings := filepath.Join(factoryDir, "settings.json")
	switch {
	case samePlatformPath(clean, root):
		return factoryPathRootHooks, root, legacy, settings
	case samePlatformPath(clean, legacy):
		return factoryPathLegacyHooks, root, legacy, settings
	case samePlatformPath(clean, settings):
		return factoryPathSettings, root, legacy, settings
	default:
		return factoryPathLocalSettings, root, legacy, settings
	}
}

func factoryStandaloneShadowsInstall(ff factoryHooksFile) bool {
	for _, event := range factoryHookEvents {
		if ff.hasEvent(event.settingsKey) {
			return true
		}
	}
	return false
}

func factorySelectedStandaloneForSettings(path string) (factoryHooksFile, string, bool, error) {
	kind, rootPath, legacyPath, _ := factoryScopePath(path)
	if kind != factoryPathSettings {
		return newFactoryHooksFile(), "", false, nil
	}
	rootExists, err := factoryConfigExists(rootPath)
	if err != nil {
		return factoryHooksFile{}, rootPath, false, err
	}
	selectedPath := rootPath
	if !rootExists {
		legacyExists, legacyErr := factoryConfigExists(legacyPath)
		if legacyErr != nil {
			return factoryHooksFile{}, legacyPath, false, legacyErr
		}
		if !legacyExists {
			return newFactoryHooksFile(), "", false, nil
		}
		selectedPath = legacyPath
	}
	standalone, err := readFactoryHooksFile(selectedPath)
	if err != nil {
		return factoryHooksFile{}, selectedPath, true, err
	}
	return standalone, selectedPath, true, nil
}

// factoryHooksDisabledSource applies Factory's event-map merge semantics to
// its global enable flag. A selected standalone value wins when present;
// otherwise settings.json supplies the effective value.
func factoryHooksDisabledSource(
	standalone factoryHooksFile,
	standalonePath string,
	standaloneExists bool,
	settings factoryHooksFile,
	settingsPath string,
) string {
	if standaloneExists {
		if disabled, present := standalone.boolSetting("hooksDisabled"); present {
			if disabled {
				return standalonePath
			}
			return ""
		}
	}
	if disabled, present := settings.boolSetting("hooksDisabled"); present && disabled {
		return settingsPath
	}
	return ""
}

// factorySettingsInstallShadow returns the selected standalone path when an
// explicit settings.json install would be at least partly inactive.
func factorySettingsInstallShadow(path string) (string, error) {
	standalone, selectedPath, exists, err := factorySelectedStandaloneForSettings(path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	if factoryStandaloneShadowsInstall(standalone) {
		return selectedPath, nil
	}
	return "", nil
}

// factoryFallbackSettingsPath returns the nested settings source only for an
// actual .factory scope. An explicit staging path such as /tmp/out/hooks.json
// still gets the canonical top-level codec without unexpectedly reading or
// modifying a sibling settings.json.
func factoryFallbackSettingsPath(path string) (string, bool) {
	if !factoryHooksPath(path) {
		return "", false
	}
	dir := filepath.Dir(path)
	parent := filepath.Base(dir)
	if runtime.GOOS == "windows" {
		if strings.EqualFold(parent, ".factory") {
			return filepath.Join(dir, "settings.json"), true
		}
		if strings.EqualFold(parent, "hooks") && strings.EqualFold(filepath.Base(filepath.Dir(dir)), ".factory") {
			return filepath.Join(filepath.Dir(dir), "settings.json"), true
		}
		return "", false
	}
	if parent == ".factory" {
		return filepath.Join(dir, "settings.json"), true
	}
	if parent == "hooks" && filepath.Base(filepath.Dir(dir)) == ".factory" {
		return filepath.Join(filepath.Dir(dir), "settings.json"), true
	}
	return "", false
}

func factoryConfigExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// readFactoryFallback reads the nested settings.json compatibility source that
// Factory merges underneath the standalone hooks.json event map.
func readFactoryFallback(path string) (string, factorySettingsFile, bool, error) {
	legacyPath, ok := factoryFallbackSettingsPath(path)
	if !ok {
		return "", factorySettingsFile{}, false, nil
	}
	exists, err := factoryConfigExists(legacyPath)
	if err != nil {
		return legacyPath, factorySettingsFile{}, false, err
	}
	if !exists {
		return legacyPath, newFactorySettingsFile(), false, nil
	}
	sf, err := readFactorySettings(legacyPath)
	return legacyPath, sf, true, err
}

// factoryLegacyStandalonePath returns Factory's former direct-schema location.
// Current clients load it only when the root hooks.json does not exist.
func factoryLegacyStandalonePath(path string) (string, bool) {
	if !factoryHooksPath(path) {
		return "", false
	}
	dir := filepath.Dir(path)
	parent := filepath.Base(dir)
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(parent, ".factory") {
			return "", false
		}
	} else if parent != ".factory" {
		return "", false
	}
	return filepath.Join(dir, "hooks", "hooks.json"), true
}

func readFactoryLegacyStandalone(path string) (string, factoryHooksFile, bool, error) {
	legacyPath, ok := factoryLegacyStandalonePath(path)
	if !ok {
		return "", factoryHooksFile{}, false, nil
	}
	exists, err := factoryConfigExists(legacyPath)
	if err != nil {
		return legacyPath, factoryHooksFile{}, false, err
	}
	if !exists {
		return legacyPath, factoryHooksFile{}, false, nil
	}
	ff, err := readFactoryHooksFile(legacyPath)
	return legacyPath, ff, true, err
}

// carryFactoryStandalone copies a legacy direct-schema file into an absent root
// canonical file, including unknown future top-level fields. Parsed event maps
// are copied separately so auspex-owned entries can be refreshed safely.
func carryFactoryStandalone(dst factoryHooksFile, src factoryHooksFile) {
	for key, value := range src.values {
		dst.values[key] = append(json.RawMessage(nil), value...)
	}
	for event, groups := range src.hooks {
		dst.hooks[event] = cloneFactoryHookGroups(groups)
	}
}

// cloneFactoryHookGroups isolates the canonical migration copy from the source
// file that is cleaned later in the same operation. Hook filtering compacts
// slices and future schema-preserving edits may touch raw field maps, so no
// mutable slice or map is shared across the two write targets.
func cloneFactoryHookGroups(groups []hookGroup) []hookGroup {
	if groups == nil {
		return nil
	}
	out := make([]hookGroup, len(groups))
	for i, group := range groups {
		out[i] = group
		out[i].fields = cloneFactoryRawFields(group.fields)
		if group.Hooks == nil {
			continue
		}
		out[i].Hooks = make([]hookRef, len(group.Hooks))
		for j, ref := range group.Hooks {
			out[i].Hooks[j] = ref
			out[i].Hooks[j].Args = append([]string(nil), ref.Args...)
			out[i].Hooks[j].fields = cloneFactoryRawFields(ref.fields)
		}
	}
	return out
}

func cloneFactoryRawFields(fields map[string]json.RawMessage) map[string]json.RawMessage {
	if fields == nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		out[key] = append(json.RawMessage(nil), value...)
	}
	return out
}

func installFactorySettingsWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}
	sf, err := readFactorySettings(path)
	if err != nil {
		return rep, err
	}
	standalone, standalonePath, standaloneExists, err := factorySelectedStandaloneForSettings(path)
	if err != nil {
		return rep, err
	}
	if disabledPath := factoryHooksDisabledSource(standalone, standalonePath, standaloneExists, sf.hooks, path); disabledPath != "" {
		return rep, fmt.Errorf("factory hooks are disabled by hooksDisabled=true in %s; enable hooks before installing auspex", disabledPath)
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	sf.removeAuspexHooks()
	sf.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeFactorySettings(path, sf); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = installMessage(enforce)
	return rep, nil
}

// installFactoryWithArgs writes Factory's current root-level standalone file.
// When only the former hooks/hooks.json exists, all of its contents are copied
// first because merely creating the root file makes Factory ignore the former
// location wholesale. For each event auspex is about to add, the installer also
// carries forward an active settings.json event that the new root event would
// otherwise shadow. Auspex-owned entries are then cleaned from every readable
// source so removing the root file later cannot reactivate an older command.
func installFactoryWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	kind, rootPath, _, _ := factoryScopePath(path)
	if kind == factoryPathLocalSettings {
		return InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}, fmt.Errorf(
			"factory does not load hooks from %s; install using --settings %s",
			path, rootPath,
		)
	}
	if kind == factoryPathLegacyHooks {
		rootExists, err := factoryConfigExists(rootPath)
		if err != nil {
			return InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}, err
		}
		if rootExists {
			return InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}, fmt.Errorf(
				"factory ignores %s while %s exists; install using --settings %s",
				path, rootPath, rootPath,
			)
		}
	}
	if kind == factoryPathSettings {
		shadowingPath, err := factorySettingsInstallShadow(path)
		if err != nil {
			return InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}, err
		}
		if shadowingPath != "" {
			return InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}, fmt.Errorf(
				"factory standalone hooks in %s override events auspex would add to %s; install using --settings %s",
				shadowingPath, path, rootPath,
			)
		}
	}
	if !factoryHooksPath(path) {
		return installFactorySettingsWithArgs(path, binary, runtimeArgs, enforce)
	}
	rep := InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}
	canonicalExisted, err := factoryConfigExists(path)
	if err != nil {
		return rep, err
	}
	canonical, err := readFactoryHooksFile(path)
	if err != nil {
		return rep, err
	}

	standalonePath, standalone, standaloneExists, standaloneErr := readFactoryLegacyStandalone(path)
	if standaloneErr != nil && !canonicalExisted {
		// Without the root file, hooks/hooks.json is the selected standalone
		// source. Do not replace and shadow content we cannot preserve.
		return rep, standaloneErr
	}
	if standaloneErr != nil {
		// A root hooks.json makes this source wholly inactive. Leave malformed
		// bytes untouched and surface the condition in the report.
		standaloneExists = false
	}

	settingsPath, settings, settingsExists, settingsErr := readFactoryFallback(path)
	selectedStandaloneExists := canonicalExisted || standaloneExists
	if settingsErr != nil && !selectedStandaloneExists {
		// With no standalone source, settings.json is the only active hook map.
		// Refuse to shadow content that cannot be inspected and preserved.
		return rep, settingsErr
	}
	if settingsErr != nil {
		// Factory ignores an independently malformed settings.json when a valid
		// standalone source is selected. Preserve it byte-for-byte and warn.
		settingsExists = false
	}

	migratedStandalone := !canonicalExisted && standaloneExists
	if migratedStandalone {
		carryFactoryStandalone(canonical, standalone)
	}
	selectedStandalonePath := path
	if !canonicalExisted && standaloneExists {
		selectedStandalonePath = standalonePath
	}
	if disabledPath := factoryHooksDisabledSource(
		canonical,
		selectedStandalonePath,
		selectedStandaloneExists,
		settings.hooks,
		settingsPath,
	); disabledPath != "" {
		return rep, fmt.Errorf("factory hooks are disabled by hooksDisabled=true in %s; enable hooks before installing auspex", disabledPath)
	}

	carriedForward := false
	if settingsExists {
		for _, event := range factoryHookEvents {
			if canonical.hasEvent(event.settingsKey) {
				continue
			}
			groups, ok := settings.hooks.hooks[event.settingsKey]
			if !ok || len(groups) == 0 {
				continue
			}
			canonical.hooks[event.settingsKey] = cloneFactoryHookGroups(groups)
			canonical.dirty[event.settingsKey] = true
			carriedForward = true
		}
	}

	// Remove every prior auspex marker, including entries under event names a
	// previous release may have used, before installing the current event set.
	canonical.removeAuspexHooks()
	standaloneChanged := standaloneExists && standalone.removeAuspexHooks()
	settingsChanged := settingsExists && settings.removeAuspexHooks()
	canonical.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)

	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	standaloneBackup := ""
	if standaloneChanged {
		standaloneBackup, err = backupIfExists(standalonePath)
		if err != nil {
			return rep, err
		}
		if rep.BackupPath == "" {
			rep.BackupPath = standaloneBackup
		}
	}
	settingsBackup := ""
	if settingsChanged {
		settingsBackup, err = backupIfExists(settingsPath)
		if err != nil {
			return rep, err
		}
		if rep.BackupPath == "" {
			rep.BackupPath = settingsBackup
		}
	}

	// Make the fully preserved root source active before cleaning its now
	// inactive predecessors. A failed migration never removes the source the
	// client was already loading.
	if err := writeFactoryHooksFile(path, canonical); err != nil {
		return rep, err
	}
	if standaloneChanged {
		if err := writeFactoryHooksFile(standalonePath, standalone); err != nil {
			return rep, err
		}
	}
	if settingsChanged {
		if err := writeFactorySettings(settingsPath, settings); err != nil {
			return rep, err
		}
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = installMessage(enforce)
	if migratedStandalone {
		rep.Message += "; migrated legacy hooks/hooks.json into hooks.json"
	}
	if carriedForward {
		rep.Message += "; preserved settings.json hooks for root event overrides"
	}
	if standaloneChanged {
		rep.Message += "; removed stale auspex entries from legacy hooks/hooks.json"
		if standaloneBackup != "" && standaloneBackup != rep.BackupPath {
			rep.Message += " (legacy hooks backup: " + standaloneBackup + ")"
		}
	}
	if settingsChanged {
		rep.Message += "; removed stale auspex entries from settings.json"
		if settingsBackup != "" && settingsBackup != rep.BackupPath {
			rep.Message += " (settings backup: " + settingsBackup + ")"
		}
	}
	if standaloneErr != nil {
		rep.Message += "; shadowed hooks/hooks.json could not be inspected: " + standaloneErr.Error()
	}
	if settingsErr != nil {
		rep.Message += "; settings.json hook source could not be inspected: " + settingsErr.Error()
	}
	return rep, nil
}

func uninstallFactorySettings(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	sf, err := readFactorySettings(path)
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
	if err := writeFactorySettings(path, sf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	return rep, nil
}

// uninstallFactory removes auspex from the root standalone map, the former
// hooks/hooks.json standalone map, and the nested settings.json map. Less
// preferred sources are written first so a failure never removes the active
// marker while leaving a dormant owned entry poised to reactivate later.
func uninstallFactory(path string) (InstallReport, error) {
	if !factoryHooksPath(path) {
		return uninstallFactorySettings(path)
	}
	rep := InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}
	kind, rootPath, _, _ := factoryScopePath(path)
	if kind == factoryPathLegacyHooks {
		rootExists, existsErr := factoryConfigExists(rootPath)
		if existsErr != nil {
			return rep, existsErr
		}
		if rootExists {
			return rep, fmt.Errorf(
				"factory ignores %s while %s exists; uninstall using --settings %s",
				path, rootPath, rootPath,
			)
		}
	}
	canonicalExists, err := factoryConfigExists(path)
	if err != nil {
		return rep, err
	}
	canonical, err := readFactoryHooksFile(path)
	if err != nil {
		return rep, err
	}

	standalonePath, standalone, standaloneExists, standaloneErr := readFactoryLegacyStandalone(path)
	if standaloneErr != nil && !canonicalExists {
		return rep, standaloneErr
	}
	if standaloneErr != nil {
		// The root source wholly shadows the former standalone location.
		standaloneExists = false
	}

	settingsPath, settings, settingsExists, settingsErr := readFactoryFallback(path)
	selectedStandaloneExists := canonicalExists || standaloneExists
	if settingsErr != nil && !selectedStandaloneExists {
		return rep, settingsErr
	}
	if settingsErr != nil {
		// Factory ignores an invalid settings.json independently of a selected
		// standalone source. Leave it untouched and report the limitation.
		settingsExists = false
	}

	canonicalChanged := canonicalExists && canonical.removeAuspexHooks()
	standaloneChanged := standaloneExists && standalone.removeAuspexHooks()
	settingsChanged := settingsExists && settings.removeAuspexHooks()
	if !canonicalChanged && !standaloneChanged && !settingsChanged {
		rep.Message = "no auspex hooks present"
		if standaloneErr != nil {
			rep.Message += "; shadowed hooks/hooks.json could not be inspected: " + standaloneErr.Error()
		}
		if settingsErr != nil {
			rep.Message += "; settings.json hook source could not be inspected: " + settingsErr.Error()
		}
		return rep, nil
	}
	if canonicalChanged {
		backup, err := backupIfExists(path)
		if err != nil {
			return rep, err
		}
		rep.BackupPath = backup
	}
	standaloneBackup := ""
	if standaloneChanged {
		standaloneBackup, err = backupIfExists(standalonePath)
		if err != nil {
			return rep, err
		}
		if rep.BackupPath == "" {
			rep.BackupPath = standaloneBackup
		}
	}
	settingsBackup := ""
	if settingsChanged {
		settingsBackup, err = backupIfExists(settingsPath)
		if err != nil {
			return rep, err
		}
		if rep.BackupPath == "" {
			rep.BackupPath = settingsBackup
		}
	}
	if err := writeFactoryUninstallChanges(
		canonicalExists,
		settingsChanged,
		func() error { return writeFactorySettings(settingsPath, settings) },
		standaloneChanged,
		func() error { return writeFactoryHooksFile(standalonePath, standalone) },
		canonicalChanged,
		func() error { return writeFactoryHooksFile(path, canonical) },
	); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	if standaloneChanged {
		rep.Message += " including legacy hooks/hooks.json"
		if standaloneBackup != "" && standaloneBackup != rep.BackupPath {
			rep.Message += " (legacy hooks backup: " + standaloneBackup + ")"
		}
	}
	if settingsChanged {
		rep.Message += " including settings.json fallback"
		if settingsBackup != "" && settingsBackup != rep.BackupPath {
			rep.Message += " (settings backup: " + settingsBackup + ")"
		}
	}
	if standaloneErr != nil {
		rep.Message += "; shadowed hooks/hooks.json could not be inspected: " + standaloneErr.Error()
	}
	if settingsErr != nil {
		rep.Message += "; settings.json hook source could not be inspected: " + settingsErr.Error()
	}
	return rep, nil
}

// writeFactoryUninstallChanges cleans sources from least to most preferred.
// With a root source, the wholly dormant legacy standalone is cleaned before
// settings (whose non-overridden events may still be active), then root. Without
// a root, settings is cleaned before the selected legacy standalone.
func writeFactoryUninstallChanges(
	canonicalExists bool,
	settingsChanged bool,
	writeSettingsSource func() error,
	standaloneChanged bool,
	writeLegacyStandalone func() error,
	canonicalChanged bool,
	writeCanonical func() error,
) error {
	if canonicalExists {
		if standaloneChanged {
			if err := writeLegacyStandalone(); err != nil {
				return err
			}
		}
		if settingsChanged {
			if err := writeSettingsSource(); err != nil {
				return err
			}
		}
	} else {
		if settingsChanged {
			if err := writeSettingsSource(); err != nil {
				return err
			}
		}
		if standaloneChanged {
			if err := writeLegacyStandalone(); err != nil {
				return err
			}
		}
	}
	if canonicalChanged {
		if err := writeCanonical(); err != nil {
			return err
		}
	}
	return nil
}

func statusFactorySettings(path string) InstallReport {
	rep := InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}
	sf, err := readFactorySettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}

	kind, rootPath, legacyPath, _ := factoryScopePath(path)
	if kind == factoryPathLocalSettings {
		rep.Message = "auspex hooks not installed: Factory does not load hooks from settings.local.json; use " + rootPath
		if sf.hasAuspexHooks() {
			rep.Message += "; inactive auspex entries remain"
		}
		return rep
	}
	if kind == factoryPathSettings {
		selectedPath := rootPath
		selectedExists, selectErr := factoryConfigExists(rootPath)
		if selectErr != nil {
			rep.Message = selectErr.Error()
			return rep
		}
		if !selectedExists {
			selectedPath = legacyPath
			selectedExists, selectErr = factoryConfigExists(legacyPath)
			if selectErr != nil {
				rep.Message = selectErr.Error()
				return rep
			}
		}
		if selectedExists {
			standalone, readErr := readFactoryHooksFile(selectedPath)
			if readErr != nil {
				rep.Message = readErr.Error()
				return rep
			}
			active, shadowed := factoryFallbackAuspexState(standalone, sf)
			disabledPath := factoryHooksDisabledSource(standalone, selectedPath, true, sf.hooks, path)
			rep.Installed = active && disabledPath == ""
			if active && disabledPath == "" {
				rep.Message = "auspex hooks installed via unshadowed settings.json events"
			} else if active {
				rep.Message = "auspex hooks present but inactive because Factory hooks are disabled by " + disabledPath
			} else {
				rep.Message = "auspex hooks not installed via active settings.json events"
			}
			if shadowed {
				rep.Message += "; auspex settings.json entries are shadowed by " + selectedPath
			}
			return rep
		}
	}

	hasAuspex := sf.hasAuspexHooks()
	disabledPath := factoryHooksDisabledSource(newFactoryHooksFile(), "", false, sf.hooks, path)
	rep.Installed = hasAuspex && disabledPath == ""
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else if hasAuspex {
		rep.Message = "auspex hooks present but inactive because Factory hooks are disabled by " + disabledPath
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

func factoryFallbackAuspexState(standalone factoryHooksFile, settings factorySettingsFile) (active, shadowed bool) {
	for event, groups := range settings.hooks.hooks {
		if !hasAuspexGroup(groups) {
			continue
		}
		if standalone.hasEvent(event) {
			shadowed = true
		} else {
			active = true
		}
	}
	return active, shadowed
}

// statusFactory mirrors both Factory precedence rules: root hooks.json wholly
// replaces hooks/hooks.json, then the selected standalone map overrides
// settings.json per event while settings-only events remain active.
func statusFactory(path string) InstallReport {
	if !factoryHooksPath(path) {
		return statusFactorySettings(path)
	}
	rep := InstallReport{Agent: AgentFactory, SettingsPath: path, Supported: true}
	kind, rootPath, _, _ := factoryScopePath(path)
	if kind == factoryPathLegacyHooks {
		rootExists, existsErr := factoryConfigExists(rootPath)
		if existsErr != nil {
			rep.Message = existsErr.Error()
			return rep
		}
		if rootExists {
			legacy, readErr := readFactoryHooksFile(path)
			if readErr != nil {
				rep.Message = readErr.Error()
				return rep
			}
			rep.Message = "auspex hooks not installed at this inactive path; Factory ignores it while " + rootPath + " exists"
			if legacy.hasAuspexHooks() {
				rep.Message += "; shadowed auspex entries remain"
			}
			return rep
		}
	}

	canonicalExists, err := factoryConfigExists(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	canonical, err := readFactoryHooksFile(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}

	standalonePath, standalone, standaloneExists, standaloneErr := readFactoryLegacyStandalone(path)
	if standaloneErr != nil && !canonicalExists {
		rep.Message = standaloneErr.Error()
		return rep
	}
	if standaloneErr != nil {
		standaloneExists = false
	}

	selected := canonical
	selectedPath := path
	selectedExists := canonicalExists
	selectedInstalled := canonicalExists && canonical.hasAuspexHooks()
	shadowedStandalone := false
	if canonicalExists {
		shadowedStandalone = standaloneExists && standalone.hasAuspexHooks()
	} else if standaloneExists {
		selected = standalone
		selectedPath = standalonePath
		selectedExists = true
		selectedInstalled = standalone.hasAuspexHooks()
	}

	settingsPath, settings, settingsExists, settingsErr := readFactoryFallback(path)
	if settingsErr != nil && !selectedExists {
		rep.Message = settingsErr.Error()
		return rep
	}
	activeSettings, shadowedSettings := false, false
	if settingsExists && settingsErr == nil {
		activeSettings, shadowedSettings = factoryFallbackAuspexState(selected, settings)
	}

	hasActiveAuspex := selectedInstalled || activeSettings
	disabledPath := factoryHooksDisabledSource(selected, selectedPath, selectedExists, settings.hooks, settingsPath)
	rep.Installed = hasActiveAuspex && disabledPath == ""
	if hasActiveAuspex && disabledPath != "" {
		if selectedInstalled {
			rep.SettingsPath = selectedPath
		} else {
			rep.SettingsPath = settingsPath
		}
		rep.Message = "auspex hooks present but inactive because Factory hooks are disabled by " + disabledPath
	} else if selectedInstalled {
		rep.SettingsPath = selectedPath
		rep.Message = "auspex hooks installed"
		if !canonicalExists {
			rep.Message += " via legacy hooks/hooks.json"
		}
	} else if activeSettings {
		rep.SettingsPath = settingsPath
		rep.Message = "auspex hooks installed via unshadowed settings.json events"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	if standaloneErr != nil {
		rep.Message += "; shadowed hooks/hooks.json could not be inspected: " + standaloneErr.Error()
	} else if shadowedStandalone {
		rep.Message += "; shadowed auspex entries remain in hooks/hooks.json"
	}
	if settingsErr != nil {
		rep.Message += "; settings.json hook source could not be inspected: " + settingsErr.Error()
	} else if shadowedSettings {
		rep.Message += "; shadowed auspex entries remain in settings.json"
	}
	return rep
}

// configReadableFactory validates the selected canonical file when it exists;
// without one, it validates the nested settings.json source Factory will load.
func configReadableFactory(path string) error {
	if !factoryHooksPath(path) {
		if _, err := readFactorySettings(path); err != nil {
			return err
		}
		kind, _, _, _ := factoryScopePath(path)
		if kind == factoryPathSettings {
			_, _, _, err := factorySelectedStandaloneForSettings(path)
			return err
		}
		return nil
	}
	canonicalExists, err := factoryConfigExists(path)
	if err != nil {
		return err
	}
	if canonicalExists {
		_, err = readFactoryHooksFile(path)
		return err
	}
	_, _, standaloneExists, err := readFactoryLegacyStandalone(path)
	if err != nil {
		return err
	}
	if standaloneExists {
		// readFactoryLegacyStandalone already parsed the selected source.
		return nil
	}
	_, _, settingsExists, err := readFactoryFallback(path)
	if err != nil {
		return err
	}
	if settingsExists {
		// readFactoryFallback already parsed the only active source.
		return nil
	}
	return nil
}

// FactoryLifecycleArgs returns the lifecycle argument names auspex wires for
// Factory, in event order, for diagnostics and tests.
func FactoryLifecycleArgs() []string {
	out := make([]string, 0, len(factoryHookEvents))
	for _, ev := range factoryHookEvents {
		out = append(out, ev.lifecycle)
	}
	return out
}
