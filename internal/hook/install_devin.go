package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// install_devin.go wires auspex into Devin CLI hooks. Project scope uses
// <cwd>/.devin/hooks.v1.json as a standalone hooks map; user scope embeds the
// same map under "hooks" in the user config. auspex keys ownership on its
// command marker and preserves foreign hooks/config keys.

const (
	// devinProjectFile is the standalone project-scope hooks file basename.
	devinProjectFile = "hooks.v1.json"
	// devinHooksKey is the key under which the hooks map lives inside the embedded
	// user-scope config.json.
	devinHooksKey = "hooks"
)

// devinHookEvent pairs a Devin hooks-map event key with the auspex lifecycle argument
// its command invokes and an optional matcher/timeout.
type devinHookEvent struct {
	// eventKey is the key in Devin's hooks map (SessionStart, UserPromptSubmit,
	// PreToolUse, PermissionRequest, PostToolUse, Stop, SessionEnd).
	eventKey string
	// lifecycle is the positional argument passed to `auspex hook <lifecycle>`.
	lifecycle string
	// timeout is the hook's timeout in seconds; 0 omits it.
	timeout int
}

// devinHookEvents is the closed set auspex wires. Tool and permission moments
// route to Devin-specific lifecycles; permission events record requests only.
var devinHookEvents = []devinHookEvent{
	{eventKey: "SessionStart", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{eventKey: "UserPromptSubmit", lifecycle: string(LifecyclePromptSubmit), timeout: promptHookTimeoutSeconds},
	{eventKey: "PreToolUse", lifecycle: string(LifecycleDevinPreTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "PermissionRequest", lifecycle: string(LifecycleDevinPermission), timeout: fastHookTimeoutSeconds},
	{eventKey: "PostToolUse", lifecycle: string(LifecycleDevinPostTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "Stop", lifecycle: string(LifecycleStop), timeout: stopHookTimeoutSeconds},
	{eventKey: "SessionEnd", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
}

// devinHooks is a Devin hooks map: event name → hook groups. It reuses the shared
// hookGroup/hookRef shapes (matcher + a list of {type,command,timeout}).
type devinHooks map[string][]hookGroup

// devinFile holds a parsed Devin config, abstracting over the two scopes. For the
// STANDALONE project file the top-level JSON IS the hooks map (foreign is empty). For
// the EMBEDDED user config.json the hooks map is one key inside a larger object whose
// other keys are kept as RAW JSON so a round-trip preserves them byte-for-byte.
type devinFile struct {
	// standalone reports whether the file's top-level JSON is the hooks map itself
	// (project scope) rather than an embedded config (user scope).
	standalone bool
	// foreign holds every embedded top-level key EXCEPT "hooks", verbatim. Always
	// empty for a standalone file.
	foreign map[string]json.RawMessage
	// hooks is the parsed hooks map (nil when absent).
	hooks devinHooks
}

// DevinProjectHooksPath returns the PROJECT-scope standalone hooks file path:
// <cwd>/.devin/hooks.v1.json.
func DevinProjectHooksPath(cwd string) string {
	return filepath.Join(cwd, ".devin", devinProjectFile)
}

// DevinUserConfigPath returns Devin's platform-specific user config path.
func DevinUserConfigPath(home string) string {
	return devinUserConfigPath(home, runtime.GOOS, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("APPDATA"))
}

func devinUserConfigPath(home, goos, xdgConfigHome, appData string) string {
	root := xdgConfigHome
	if goos == "windows" {
		root = appData
		if root == "" {
			root = filepath.Join(home, "AppData", "Roaming")
		}
	} else if root == "" {
		root = filepath.Join(home, ".config")
	}
	return filepath.Join(root, "devin", "config.json")
}

// isDevinStandalone reports whether a Devin config path is the standalone project
// hooks file (its base is hooks.v1.json) rather than the embedded user config.json.
func isDevinStandalone(path string) bool {
	return strings.EqualFold(filepath.Base(path), devinProjectFile)
}

// devinCommandWithArgs builds the hook command auspex writes for a Devin event. It passes the
// auspex lifecycle as the positional argument (the live handler reads it via
// ResolveLifecycle, which for Devin resolves through resolveDevinEvent) and carries
// the auspex marker so detection survives a renamed binary. The binary path and runtime
// args are shell-quoted because Devin runs the command through a shell before auspex
// starts.
func devinCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentDevin, runtimeArgs, enforce)
}

// readDevinFile loads a Devin config from path, detecting the scope from the basename.
// A standalone file's top-level JSON is parsed directly as the hooks map; an embedded
// config splits the "hooks" key out and keeps every foreign key as raw JSON. A missing
// or empty file is not an error: it yields an empty file value so install can create it.
func readDevinFile(path string) (devinFile, error) {
	df := devinFile{standalone: isDevinStandalone(path), foreign: map[string]json.RawMessage{}}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return df, nil
		}
		return devinFile{}, err
	}
	if len(data) == 0 {
		return df, nil
	}
	if df.standalone {
		var h devinHooks
		if err := json.Unmarshal(data, &h); err != nil {
			return devinFile{}, fmt.Errorf("parse %s: %w", path, err)
		}
		df.hooks = h
		return df, nil
	}
	// Devin's user config (~/.config/devin/config.json) is a comment-enabled / JSONC
	// file (documented at docs.devin.ai), so strip // line and /* */ block comments
	// before the strict stdlib unmarshal — without it install/status/uninstall would
	// FAIL on a commented config. The stripper is in-string aware so // or /* inside a
	// JSON string value (e.g. a URL or path) is preserved untouched. auspex parses
	// comment-enabled Devin config but re-serializes canonical JSON on write; user
	// comments in config.json are not round-tripped.
	// The standalone .devin/hooks.v1.json path stays strict (it is a pure hooks map
	// written by auspex and is never comment-bearing).
	data, err = stripJSONComments(data)
	if err != nil {
		return devinFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return devinFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	for k, v := range top {
		if k == devinHooksKey {
			var h devinHooks
			if err := json.Unmarshal(v, &h); err != nil {
				return devinFile{}, fmt.Errorf("parse hooks in %s: %w", path, err)
			}
			df.hooks = h
			continue
		}
		df.foreign[k] = v
	}
	return df, nil
}

// stripJSONComments removes JSONC // line comments and /* */ block comments from a
// JSON byte slice, plus trailing commas, returning a slice the stdlib encoding/json
// can parse strictly. Comments are replaced with JSON whitespace rather than simply
// deleted, so two otherwise separate tokens cannot be accidentally joined into a
// different valid value. It is a dependency-free byte scanner that tracks JSON string
// state (and backslash escapes) so a // or /* sequence appearing INSIDE a string
// literal — e.g. a "https://..." URL or a "/path/*glob*/" value — is preserved
// byte-for-byte and never mistaken for a comment. It is shared by the explicitly
// comment-enabled Devin and Factory config readers; their generated output remains
// canonical JSON.
func stripJSONComments(data []byte) ([]byte, error) {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			// A space keeps a comment between tokens from joining them. Skip to the
			// end of the line; the newline itself is retained on the next iteration.
			out = append(out, ' ')
			for i+1 < len(data) && data[i+1] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			// Preserve a whitespace boundary and embedded newlines for safe token
			// separation and useful parse-error line numbers.
			out = append(out, ' ')
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			if i+1 >= len(data) {
				return nil, fmt.Errorf("unterminated block comment")
			}
			i++ // consume the '/' of the closing */
		default:
			out = append(out, c)
		}
	}
	return stripTrailingCommas(out), nil
}

// stripTrailingCommas removes a comma that is immediately followed (ignoring
// whitespace) by a closing } or ] so JSONC trailing commas parse under the strict
// stdlib decoder. It is in-string aware for the same reason as stripJSONComments: a
// comma inside a string value is left untouched. Run after comment removal.
func stripTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			// A JSONC trailing comma still requires a value before it. Leaving
			// commas after an opener, colon, or another comma in place lets the
			// strict decoder reject malformed constructs such as [,] and {"x":,}.
			k := len(out) - 1
			for k >= 0 && (out[k] == ' ' || out[k] == '\t' || out[k] == '\n' || out[k] == '\r') {
				k--
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') && k >= 0 && !strings.ContainsRune("[{:,", rune(out[k])) {
				continue // drop the trailing comma
			}
		}
		out = append(out, c)
	}
	return out
}

// hasAuspexHooks reports whether at least one auspex-marked hook command is wired.
func (df devinFile) hasAuspexHooks() bool {
	for _, groups := range df.hooks {
		if hasAuspexGroup(groups) {
			return true
		}
	}
	return false
}

// applyAuspexHooksWithArgs (re)builds auspex's groups, replacing any prior auspex group per
// event so a re-install is idempotent — each wired event holds exactly one auspex
// group plus any foreign group untouched. An omitted matcher covers all tools.
func (df *devinFile) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	if df.hooks == nil {
		df.hooks = devinHooks{}
	}
	for _, ev := range devinHookEvents {
		groups := stripAuspexGroups(df.hooks[ev.eventKey])
		groups = append(groups, hookGroup{
			Hooks: []hookRef{{
				Type:    "command",
				Command: devinCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.eventKey == "PreToolUse"),
				Timeout: ev.timeout,
			}},
		})
		df.hooks[ev.eventKey] = groups
	}
}

// removeAuspexHooks strips every auspex-marked hook (dropping now-empty groups and
// event keys), reporting whether anything was removed. Foreign top-level keys and
// foreign hook groups are left intact.
func (df *devinFile) removeAuspexHooks() bool {
	if !df.isAuspexRecognized() {
		return false
	}
	changed := false
	for key, groups := range df.hooks {
		kept := stripAuspexGroups(groups)
		if len(kept) != len(groups) || hasAuspexGroup(groups) {
			changed = true
		}
		if len(kept) == 0 {
			delete(df.hooks, key)
		} else {
			df.hooks[key] = kept
		}
	}
	return changed
}

// isAuspexRecognized reports whether the file carries any auspex hook command, so
// uninstall touches only files auspex actually owns and leaves an unrecognized foreign
// file untouched. auspex always writes the marker on its commands, so real auspex
// files still uninstall.
func (df devinFile) isAuspexRecognized() bool {
	for _, groups := range df.hooks {
		if hasAuspexGroup(groups) {
			return true
		}
	}
	return false
}

// isEmpty reports whether the file would serialize to an object with no meaningful
// content (no hooks and, for an embedded config, no foreign keys). An uninstall that
// empties a STANDALONE project file removes it; an emptied EMBEDDED config keeps its
// foreign keys and only drops the hooks key.
func (df devinFile) isEmpty() bool {
	return len(df.hooks) == 0 && len(df.foreign) == 0
}

// marshal renders the file back to indented JSON. A standalone file marshals the hooks
// map directly as the top-level object ({} when empty). An embedded config marshals
// every foreign key verbatim plus the hooks key when non-empty (the hooks key is
// dropped when empty, leaving the rest of config.json intact).
func (df devinFile) marshal() ([]byte, error) {
	if df.standalone {
		hooks := df.hooks
		if hooks == nil {
			hooks = devinHooks{}
		}
		return json.MarshalIndent(hooks, "", "  ")
	}
	out := make(map[string]json.RawMessage, len(df.foreign)+1)
	for k, v := range df.foreign {
		out[k] = v
	}
	if len(df.hooks) > 0 {
		data, err := json.Marshal(df.hooks)
		if err != nil {
			return nil, err
		}
		out[devinHooksKey] = data
	}
	return json.MarshalIndent(out, "", "  ")
}

// installDevinWithArgs writes auspex's hook entries into a Devin config. It creates the parent
// dir if missing (0700), is idempotent, and backs the pristine file up before the
// first write.
func installDevinWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentDevin, SettingsPath: path, Supported: true}
	df, err := readDevinFile(path)
	if err != nil {
		return rep, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	df.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeDevinFile(path, df); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = installMessage(enforce)
	return rep, nil
}

// uninstallDevin removes auspex's hook entries from a Devin config, leaving any foreign
// top-level key or foreign hook group intact. When a STANDALONE project file is emptied
// (auspex was its only content), the file is removed; an EMBEDDED config keeps its
// foreign keys and only drops the now-empty hooks key. A missing file or absent auspex
// content is a no-op (Changed=false).
func uninstallDevin(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentDevin, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no hooks file; nothing to remove"
		return rep, nil
	}
	df, err := readDevinFile(path)
	if err != nil {
		return rep, err
	}
	if !df.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	// A standalone project file with nothing left is removed rather than left as a
	// bare {} object. An embedded config is never removed — it holds foreign keys (or
	// at minimum is a foreign-owned file) — so it is rewritten with the hooks key
	// dropped.
	if df.standalone && df.isEmpty() {
		if err := os.Remove(path); err != nil {
			return rep, err
		}
		rep.Changed = true
		rep.Message = "removed auspex hooks (hooks file now empty; removed)"
		return rep, nil
	}
	if err := writeDevinFile(path, df); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	return rep, nil
}

// statusDevin reports whether auspex hooks are present in a Devin config, without
// modifying anything.
func statusDevin(path string) InstallReport {
	rep := InstallReport{Agent: AgentDevin, SettingsPath: path, Supported: true}
	df, err := readDevinFile(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = df.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex hooks installed"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

// writeDevinFile renders and atomically writes a Devin config. It shares
// writeFileAtomic for identical durability and 0600 permission guarantees.
func writeDevinFile(path string, df devinFile) error {
	data, err := df.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// DevinLifecycleArgs returns the lifecycle argument names auspex wires for Devin, in
// event order, for diagnostics and tests.
func DevinLifecycleArgs() []string {
	out := make([]string, 0, len(devinHookEvents))
	for _, ev := range devinHookEvents {
		out = append(out, ev.lifecycle)
	}
	return out
}
