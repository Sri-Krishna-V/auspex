package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Hermes stores hooks as event -> flat refs under a top-level "hooks" key.
// Auspex preserves foreign config nodes and removes only its marked refs.
const hermesHooksKey = "hooks"

// hermesRef is one entry in Hermes's flat per-event hook list.
type hermesRef struct {
	Matcher string `yaml:"matcher,omitempty"`
	Command string `yaml:"command"`
	Timeout int    `yaml:"timeout,omitempty"`
}

type hermesHookEvent struct {
	eventKey  string
	lifecycle string
	timeout   int
}

// hermesHookEvents is the closed normalized subset auspex wires. Tool and
// approval events use Hermes-specific lifecycles. on_session_end is deliberately
// omitted because Hermes fires it after every run_conversation turn; the durable
// session boundary is on_session_finalize. on_session_reset is followed by
// on_session_start for the new identity, so wiring both would duplicate starts.
// pre_verify, gateway dispatch, and transform callbacks are policy/bookkeeping
// surfaces rather than distinct normalized agent actions.
var hermesHookEvents = []hermesHookEvent{
	{eventKey: "on_session_start", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{eventKey: "pre_llm_call", lifecycle: string(LifecyclePromptSubmit), timeout: promptHookTimeoutSeconds},
	{eventKey: "post_llm_call", lifecycle: string(LifecycleAssistant), timeout: promptHookTimeoutSeconds},
	{eventKey: "pre_tool_call", lifecycle: string(LifecycleHermesPreTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "post_tool_call", lifecycle: string(LifecycleHermesPostTool), timeout: fastHookTimeoutSeconds},
	{eventKey: "pre_approval_request", lifecycle: string(LifecycleHermesPermission), timeout: fastHookTimeoutSeconds},
	{eventKey: "post_approval_response", lifecycle: string(LifecycleHermesPermissionResult), timeout: fastHookTimeoutSeconds},
	{eventKey: "subagent_start", lifecycle: string(LifecycleSessionStart), timeout: fastHookTimeoutSeconds},
	{eventKey: "subagent_stop", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
	{eventKey: "on_session_finalize", lifecycle: string(LifecycleSessionEnd), timeout: fastHookTimeoutSeconds},
}

type hermesHooks map[string][]hermesRef

// hermesFile holds a parsed Hermes config. The hooks map is one key inside a larger
// object whose other keys are kept verbatim (as decoded yaml.Node values) so a
// round-trip preserves them.
type hermesFile struct {
	// root retains foreign nodes, comments, and top-level key order.
	root *yaml.Node
	// foreign is used for emptiness checks; output order comes from root.
	foreign map[string]*yaml.Node
	hooks   hermesHooks
}

// HermesUserConfigPath returns the active profile config. HERMES_HOME is how
// Hermes selects non-default profiles.
func HermesUserConfigPath(home string) string {
	return hermesUserConfigPath(home, runtime.GOOS, os.Getenv("LOCALAPPDATA"), os.Getenv("HERMES_HOME"))
}

func hermesUserConfigPath(home, goos, localAppData, hermesHome string) string {
	root := strings.TrimSpace(hermesHome)
	if root == "" && goos == "windows" {
		root = strings.TrimSpace(localAppData)
		if root == "" {
			root = filepath.Join(home, "AppData", "Local")
		}
		root = filepath.Join(root, "hermes")
	} else if root == "" {
		root = filepath.Join(home, ".hermes")
	}
	return filepath.Join(root, "config.yaml")
}

// isHermesUserScope reports whether a Hermes config path is the supported active-profile
// config ($HERMES_HOME/config.yaml or the platform default) rather than a project path.
// Hermes does not document project shell-hook config, so install rejects any
// other path.
func isHermesUserScope(path string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	want, err := filepath.Abs(HermesUserConfigPath(home))
	if err != nil {
		return false
	}
	got, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return samePlatformPath(got, want)
}

// hermesCommandWithArgs builds the hook command auspex writes for a Hermes event. It passes the
// auspex lifecycle as the positional argument (the live handler reads it via
// ResolveLifecycle, which for Hermes resolves through resolveHermesEvent) and carries
// the auspex marker so detection survives a renamed binary. The binary path and runtime
// args are quoted for Hermes's shlex.split parser; Hermes launches the resulting argv with
// shell=false.
func hermesCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentHermes, runtimeArgs, enforce)
}

// readHermesFile loads a Hermes config from path, splitting the "hooks" key out for
// editing and keeping every foreign top-level key as a decoded yaml.Node. A missing or
// empty file is not an error: it yields an empty file value so install can create it.
func readHermesFile(path string) (hermesFile, error) {
	hf := hermesFile{foreign: map[string]*yaml.Node{}}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hf, nil
		}
		return hermesFile{}, err
	}
	if len(data) == 0 {
		return hf, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return hermesFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	// An empty document (only comments/whitespace) decodes to a zero Node with no
	// content; treat it as an empty config so install can create the hooks map.
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return hf, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return hermesFile{}, fmt.Errorf("parse %s: top-level YAML is not a map", path)
	}
	hf.root = root
	hooksSeen := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		val := root.Content[i+1]
		if key.Value == hermesHooksKey {
			if hooksSeen {
				return hermesFile{}, fmt.Errorf("parse %s: duplicate top-level hooks key", path)
			}
			hooksSeen = true
			var h hermesHooks
			if err := val.Decode(&h); err != nil {
				return hermesFile{}, fmt.Errorf("parse hooks in %s: %w", path, err)
			}
			hf.hooks = h
			continue
		}
		hf.foreign[key.Value] = val
	}
	return hf, nil
}

// hasAuspexHooks reports whether at least one auspex-marked hook command is wired.
func (hf hermesFile) hasAuspexHooks() bool {
	for _, refs := range hf.hooks {
		if hasAuspexRef(refs) {
			return true
		}
	}
	return false
}

func (hf hermesFile) hookState() (complete, any bool) {
	complete = true
	any = hf.hasAuspexHooks()
	for _, event := range hermesHookEvents {
		complete = complete && hasAuspexRef(hf.hooks[event.eventKey])
	}
	return complete, any
}

// hasAuspexRef reports whether any ref in the slice carries a auspex hook command.
func hasAuspexRef(refs []hermesRef) bool {
	for _, ref := range refs {
		if isAuspexHookCommand(ref.Command) {
			return true
		}
	}
	return false
}

// stripAuspexRefs returns refs with every auspex-marked ref removed, preserving foreign
// refs in order. A nil/empty input yields nil.
func stripAuspexRefs(refs []hermesRef) []hermesRef {
	var kept []hermesRef
	for _, ref := range refs {
		if !isAuspexHookCommand(ref.Command) {
			kept = append(kept, ref)
		}
	}
	return kept
}

// applyAuspexHooksWithArgs (re)builds auspex's refs, replacing any prior auspex ref per event so
// a re-install is idempotent — each wired event holds exactly one auspex ref plus any
// foreign ref untouched. An omitted matcher covers all tools.
func (hf *hermesFile) applyAuspexHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	if hf.hooks == nil {
		hf.hooks = hermesHooks{}
	}
	for _, ev := range hermesHookEvents {
		refs := stripAuspexRefs(hf.hooks[ev.eventKey])
		refs = append(refs, hermesRef{
			Command: hermesCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.eventKey == "pre_tool_call"),
			Timeout: ev.timeout,
		})
		hf.hooks[ev.eventKey] = refs
	}
}

// removeAuspexHooks strips every auspex-marked ref (dropping now-empty event keys),
// reporting whether anything was removed. Foreign top-level keys and foreign refs are
// left intact.
func (hf *hermesFile) removeAuspexHooks() bool {
	if !hf.hasAuspexHooks() {
		return false
	}
	changed := false
	for key, refs := range hf.hooks {
		kept := stripAuspexRefs(refs)
		if len(kept) != len(refs) {
			changed = true
		}
		if len(kept) == 0 {
			delete(hf.hooks, key)
		} else {
			hf.hooks[key] = kept
		}
	}
	return changed
}

// isEmpty reports whether the file would serialize to a map with no meaningful content
// (no hooks and no foreign keys). An uninstall (or empty install) that empties the file
// removes it rather than leaving a bare object behind.
func (hf hermesFile) isEmpty() bool {
	return len(hf.hooks) == 0 && len(hf.foreign) == 0
}

// marshal replaces only the hooks node while preserving foreign nodes, comments,
// and key order. Comments inside the managed hooks node are not retained.
func (hf hermesFile) marshal() ([]byte, error) {
	var hooksValue *yaml.Node
	if len(hf.hooks) > 0 {
		var hooksNode yaml.Node
		if err := hooksNode.Encode(hf.hooks); err != nil {
			return nil, err
		}
		hooksValue = &hooksNode
	}

	root := &yaml.Node{Kind: yaml.MappingNode}
	if hf.root == nil {
		if hooksValue != nil {
			root.Content = append(root.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: hermesHooksKey}, hooksValue)
		}
		doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
		return yaml.Marshal(doc)
	}

	root.Style = hf.root.Style
	root.Tag = hf.root.Tag
	root.HeadComment = hf.root.HeadComment
	root.LineComment = hf.root.LineComment
	root.FootComment = hf.root.FootComment

	hooksSpliced := false
	for i := 0; i+1 < len(hf.root.Content); i += 2 {
		key := hf.root.Content[i]
		val := hf.root.Content[i+1]
		if key.Value == hermesHooksKey {
			if hooksValue != nil {
				root.Content = append(root.Content, key, hooksValue)
			}
			hooksSpliced = true
			continue
		}
		root.Content = append(root.Content, key, val)
	}
	if !hooksSpliced && hooksValue != nil {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: hermesHooksKey}, hooksValue)
	}

	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
	return yaml.Marshal(doc)
}

// installHermesWithArgs writes auspex's entries to the active-profile config.
func installHermesWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentHermes, SettingsPath: path, Supported: true}
	if !isHermesUserScope(path) {
		return rep, fmt.Errorf("hermes endpoint hooks support only its user config; use the default path instead of --settings")
	}
	hf, err := readHermesFile(path)
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
	hf.applyAuspexHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeHermesFile(path, hf); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	rep.Message = installMessage(enforce) + "; restart active Hermes processes, then approve each event/command on first use (non-interactive: --accept-hooks, HERMES_ACCEPT_HOOKS=1, or hooks_auto_accept: true)"
	return rep, nil
}

// uninstallHermes removes auspex's hook entries from a Hermes config, leaving any foreign
// top-level key or foreign ref intact. When auspex was the only content, the emptied file
// is removed rather than left as a bare object. A missing file or absent auspex content
// is a no-op (Changed=false). It does NOT apply the user-scope guard: removing auspex's
// own entries from any path auspex may have written is always safe.
func uninstallHermes(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentHermes, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no hooks file; nothing to remove"
		return rep, nil
	}
	hf, err := readHermesFile(path)
	if err != nil {
		return rep, err
	}
	if !hf.removeAuspexHooks() {
		rep.Message = "no auspex hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if hf.isEmpty() {
		if err := os.Remove(path); err != nil {
			return rep, err
		}
		rep.Changed = true
		rep.Message = "removed auspex hooks (hooks file now empty; removed)"
		return rep, nil
	}
	if err := writeHermesFile(path, hf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex hooks"
	return rep, nil
}

// statusHermes reports whether auspex hooks are present in a Hermes config, without
// modifying anything.
func statusHermes(path string) InstallReport {
	rep := InstallReport{Agent: AgentHermes, SettingsPath: path, Supported: true}
	hf, err := readHermesFile(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	complete, any := hf.hookState()
	rep.Installed = complete
	if complete {
		rep.Message = "auspex hooks installed"
	} else if any {
		rep.Message = "partial auspex Hermes hook install"
	} else {
		rep.Message = "auspex hooks not installed"
	}
	return rep
}

// writeHermesFile renders and atomically writes a Hermes config. It shares
// writeFileAtomic for identical durability and 0600 permission guarantees.
func writeHermesFile(path string, hf hermesFile) error {
	data, err := hf.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// HermesLifecycleArgs returns the lifecycle argument names auspex wires for Hermes, in
// event order, for diagnostics and tests.
func HermesLifecycleArgs() []string {
	out := make([]string, 0, len(hermesHookEvents))
	for _, ev := range hermesHookEvents {
		out = append(out, ev.lifecycle)
	}
	return out
}
