package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const crushConfigFile = "crush.json"

// crushHookRef is Crush's flat hooks.<event>[] entry. Unknown fields are kept
// so installing auspex does not erase options added by a newer Crush release.
type crushHookRef struct {
	Name    string
	Matcher string
	Command string
	Timeout int
	fields  map[string]json.RawMessage
}

func (h *crushHookRef) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name    string `json:"name"`
		Matcher string `json:"matcher"`
		Command string `json:"command"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &h.fields); err != nil {
		return err
	}
	h.Name, h.Matcher, h.Command, h.Timeout = wire.Name, wire.Matcher, wire.Command, wire.Timeout
	return nil
}

func (h crushHookRef) MarshalJSON() ([]byte, error) {
	out := cloneRawFields(h.fields)
	if h.Name != "" {
		if err := setJSONField(out, "name", h.Name); err != nil {
			return nil, err
		}
	}
	if h.Matcher != "" {
		if err := setJSONField(out, "matcher", h.Matcher); err != nil {
			return nil, err
		}
	}
	if err := setJSONField(out, "command", h.Command); err != nil {
		return nil, err
	}
	if h.Timeout != 0 {
		if err := setJSONField(out, "timeout", h.Timeout); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}

type crushFile struct {
	values map[string]json.RawMessage
	hooks  map[string][]crushHookRef
}

// CrushConfigPath returns Crush's user-level config. CRUSH_GLOBAL_CONFIG is a
// directory override in Crush source; Crush appends crush.json to it.
func CrushConfigPath(home string) string {
	if root := os.Getenv("CRUSH_GLOBAL_CONFIG"); root != "" {
		return filepath.Join(root, crushConfigFile)
	}
	root := os.Getenv("XDG_CONFIG_HOME")
	if root == "" {
		root = filepath.Join(home, ".config")
	}
	return filepath.Join(root, "crush", crushConfigFile)
}

func readCrushFile(path string) (crushFile, error) {
	cf := crushFile{
		values: map[string]json.RawMessage{},
		hooks:  map[string][]crushHookRef{},
	}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cf, nil
		}
		return crushFile{}, err
	}
	if len(data) == 0 {
		return cf, nil
	}
	if err := json.Unmarshal(data, &cf.values); err != nil {
		return crushFile{}, fmt.Errorf("parse Crush config %s: %w", path, err)
	}
	if raw, ok := cf.values["hooks"]; ok {
		if err := json.Unmarshal(raw, &cf.hooks); err != nil {
			return crushFile{}, fmt.Errorf("parse hooks in Crush config %s: %w", path, err)
		}
	}
	if cf.hooks == nil {
		cf.hooks = map[string][]crushHookRef{}
	}
	return cf, nil
}

func (cf crushFile) marshal() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(cf.values)+1)
	for key, value := range cf.values {
		if key != "hooks" {
			out[key] = value
		}
	}
	if len(cf.hooks) > 0 {
		hooks, err := json.Marshal(cf.hooks)
		if err != nil {
			return nil, err
		}
		out["hooks"] = hooks
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (cf crushFile) hasAuspexHooks() bool {
	for _, refs := range cf.hooks {
		for _, ref := range refs {
			if isAuspexHookCommand(ref.Command) {
				return true
			}
		}
	}
	return false
}

func (cf crushFile) removeAuspexHooks() bool {
	changed := false
	for event, refs := range cf.hooks {
		kept := refs[:0]
		for _, ref := range refs {
			if isAuspexHookCommand(ref.Command) {
				changed = true
				continue
			}
			kept = append(kept, ref)
		}
		if len(kept) == 0 {
			delete(cf.hooks, event)
		} else {
			cf.hooks[event] = kept
		}
	}
	return changed
}

func (cf crushFile) applyAuspexHook(binary string, runtimeArgs []string, enforce bool) {
	cf.removeAuspexHooks()
	command := buildHookCommand(runtime.GOOS, binary, string(LifecyclePreTool), AgentCrush, runtimeArgs, enforce)
	cf.hooks["PreToolUse"] = append(cf.hooks["PreToolUse"], crushHookRef{
		Name:    "auspex endpoint activity monitor",
		Command: command,
		Timeout: fastHookTimeoutSeconds,
	})
}

func writeCrushFile(path string, cf crushFile) error {
	data, err := cf.marshal()
	if err != nil {
		return fmt.Errorf("marshal Crush config: %w", err)
	}
	return writeFileAtomic(path, data)
}

func installCrushWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCrush, SettingsPath: path, Supported: true}
	cf, err := readCrushFile(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	cf.applyAuspexHook(binary, runtimeArgs, enforce)
	if err := writeCrushFile(path, cf); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed Crush PreToolUse hook (restart Crush to load external config changes)"
	if enforce {
		rep.Message = "installed Crush PreToolUse hook in enforce mode (restart Crush to load external config changes)"
	}
	return rep, nil
}

func uninstallCrush(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCrush, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no Crush config; nothing to remove"
		return rep, nil
	}
	cf, err := readCrushFile(path)
	if err != nil {
		return rep, err
	}
	if !cf.removeAuspexHooks() {
		rep.Message = "no auspex Crush hook present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeCrushFile(path, cf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed auspex Crush hook (restart Crush to load external config changes)"
	return rep, nil
}

func statusCrush(path string) InstallReport {
	rep := InstallReport{Agent: AgentCrush, SettingsPath: path, Supported: true}
	cf, err := readCrushFile(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = cf.hasAuspexHooks()
	if rep.Installed {
		rep.Message = "auspex Crush PreToolUse hook installed"
	} else {
		rep.Message = "auspex Crush PreToolUse hook not installed"
	}
	return rep
}
