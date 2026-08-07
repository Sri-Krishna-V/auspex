package hook

import (
	"path/filepath"
	"strings"
	"testing"
)

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PI_CODING_AGENT_DIR", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	t.Setenv("QWEN_CODE_SYSTEM_SETTINGS_PATH", "")
	t.Setenv("CLINE_DIR", "")
	t.Setenv("CLINE_HOOKS_DIR", "")
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	if home == "" {
		t.Setenv("APPDATA", "")
		t.Setenv("LOCALAPPDATA", "")
		return
	}
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
}

func hookCommandText(raw string) string {
	scripts := decodedHookCommands(raw)
	if len(scripts) == 0 {
		return raw
	}
	for i := range scripts {
		// PowerShell serializes adjacent argv values as 'arg' 'arg'. Joining
		// those delimiters lets the same semantic assertions cover POSIX text.
		scripts[i] = strings.ReplaceAll(scripts[i], "' '", " ")
	}
	return raw + "\n" + strings.Join(scripts, "\n")
}
