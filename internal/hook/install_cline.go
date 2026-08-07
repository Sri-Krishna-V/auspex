package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type clineHookEvent struct {
	name      string
	lifecycle string
}

var clineHookEvents = []clineHookEvent{
	{name: "TaskStart", lifecycle: "session-start"},
	{name: "TaskResume", lifecycle: "session-start"},
	{name: "UserPromptSubmit", lifecycle: "prompt-submit"},
	{name: "PreToolUse", lifecycle: "pre-tool"},
	{name: "PostToolUse", lifecycle: "post-tool"},
	{name: "TaskComplete", lifecycle: "session-end"},
	{name: "TaskCancel", lifecycle: "session-end"},
	{name: "TaskError", lifecycle: "session-end"},
	{name: "SessionShutdown", lifecycle: "session-end"},
}

// ClineRootPath returns the current Cline CLI/SDK global config root.
func ClineRootPath(home string) string {
	root := strings.TrimSpace(os.Getenv("CLINE_DIR"))
	if root == "" {
		root = filepath.Join(home, ".cline")
	}
	return root
}

// ClineHooksPath returns the primary or explicitly injected hook directory.
// The extension's legacy ~/Documents/Cline/Hooks directory remains available
// via --settings; legacy Unix hooks there must also be enabled in Cline's Hooks
// tab.
func ClineHooksPath(home string) string {
	if root := strings.TrimSpace(os.Getenv("CLINE_HOOKS_DIR")); root != "" {
		return root
	}
	root := ClineRootPath(home)
	return filepath.Join(root, "hooks")
}

func clineHookPath(dir, name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, name+".ps1")
	}
	return filepath.Join(dir, name)
}

func clineHookSource(binary string, event clineHookEvent, runtimeArgs []string, enforce bool) string {
	return clineHookSourceForOS(runtime.GOOS, binary, event, runtimeArgs, enforce)
}

func clineHookSourceForOS(goos, binary string, event clineHookEvent, runtimeArgs []string, enforce bool) string {
	args := hookInvocationArgs(event.lifecycle, AgentCline, runtimeArgs, enforce && event.name == "PreToolUse")
	if goos == "windows" {
		var b strings.Builder
		b.WriteString("# " + auspexHookMarker + " auspex-managed Cline hook\r\n$global:LASTEXITCODE = 1\r\n$payload = [Console]::In.ReadToEnd()\r\n$output = $payload | & ")
		b.WriteString(powerShellQuote(binary))
		for _, arg := range args {
			b.WriteByte(' ')
			b.WriteString(powerShellQuote(arg))
		}
		b.WriteString("\r\n$status = $LASTEXITCODE\r\n")
		b.WriteString("if ($status -ne 0 -or [string]::IsNullOrWhiteSpace(($output -join [Environment]::NewLine))) {\r\n")
		b.WriteString("  Write-Output '{\"cancel\":false}'\r\n  exit 0\r\n}\r\n")
		b.WriteString("Write-Output ($output -join [Environment]::NewLine)\r\nexit 0\r\n")
		return b.String()
	}
	cmd := shellQuote(binary)
	for _, arg := range args {
		cmd += " " + shellQuote(arg)
	}
	return "#!/bin/sh\n# " + auspexHookMarker + " auspex-managed Cline hook\n" +
		"output=$(" + cmd + ")\nstatus=$?\n" +
		"if [ \"$status\" -ne 0 ] || [ -z \"$output\" ]; then\n" +
		"  printf '%s\\n' '{\"cancel\":false}'\n  exit 0\nfi\n" +
		"printf '%s\\n' \"$output\"\n"
}

func isAuspexClineHook(path string) bool {
	_, owned, err := clineHookOwnership(path)
	return err == nil && owned
}

func clineHookOwnership(path string) (exists, owned bool, err error) {
	return textHookFileOwnership(path, auspexHookMarker, "auspex-managed Cline hook")
}

func configReadableCline(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: Cline hooks path is not a directory", dir)
	}
	for _, event := range clineHookEvents {
		if _, _, err := clineHookOwnership(clineHookPath(dir, event.name)); err != nil {
			return err
		}
	}
	return nil
}

func installClineWithArgs(dir, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCline, SettingsPath: dir, Supported: true}
	for _, event := range clineHookEvents {
		path := clineHookPath(dir, event.name)
		exists, owned, err := clineHookOwnership(path)
		if err != nil {
			return rep, err
		}
		if exists && !owned {
			return rep, fmt.Errorf("refusing to overwrite existing non-auspex Cline hook at %s", path)
		}
	}
	for _, event := range clineHookEvents {
		path := clineHookPath(dir, event.name)
		if err := writeFileAtomicMode(path, []byte(clineHookSource(binary, event, runtimeArgs, enforce)), 0o700, 0o700); err != nil {
			return rep, err
		}
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = "installed auspex Cline CLI hooks (restart Cline; legacy extension hooks under ~/Documents/Cline/Hooks must also be enabled in the Hooks tab)"
	if enforce {
		rep.Message = "installed auspex Cline CLI hooks in enforce mode (restart Cline; legacy extension hooks under ~/Documents/Cline/Hooks must also be enabled in the Hooks tab)"
	}
	return rep, nil
}

func uninstallCline(dir string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCline, SettingsPath: dir, Supported: true}
	ownedPaths := make([]string, 0, len(clineHookEvents))
	for _, event := range clineHookEvents {
		path := clineHookPath(dir, event.name)
		_, owned, err := clineHookOwnership(path)
		if err != nil {
			return rep, err
		}
		if owned {
			ownedPaths = append(ownedPaths, path)
		}
	}
	changed := false
	for _, path := range ownedPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return rep, err
		}
		changed = true
	}
	rep.Changed = changed
	if changed {
		rep.Message = "removed auspex Cline hooks"
	} else {
		rep.Message = "no auspex Cline hooks present"
	}
	return rep, nil
}

func statusCline(dir string) InstallReport {
	rep := InstallReport{Agent: AgentCline, SettingsPath: dir, Supported: true}
	installed := 0
	for _, event := range clineHookEvents {
		if isAuspexClineHook(clineHookPath(dir, event.name)) {
			installed++
		}
	}
	rep.Installed = installed == len(clineHookEvents)
	if rep.Installed {
		rep.Message = "auspex Cline hooks installed; restart any active Cline process"
	} else if installed > 0 {
		rep.Message = fmt.Sprintf("partial auspex Cline install (%d/%d hooks)", installed, len(clineHookEvents))
	} else {
		rep.Message = "auspex Cline hooks not installed"
	}
	return rep
}
