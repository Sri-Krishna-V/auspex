package hook

// VSCodeHooksPath returns the shared Copilot user hook file. VS Code and
// Copilot CLI both load ~/.copilot/hooks/*.json, so auspex installs one sensor
// rather than two commands that would double-report every lifecycle event.
func VSCodeHooksPath(home string) string {
	return CopilotSettingsPath(home)
}

// The vscode install target is a compatibility alias for the shared Copilot
// hook surface. The command itself uses --agent copilot; Map distinguishes VS
// Code payloads and stamps source_agent="vscode".
func installVSCodeWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep, err := installCopilotAt(path, binary, runtimeArgs, false, enforce)
	rep.Agent = AgentVSCode
	if err == nil {
		rep.Message = "installed shared Copilot CLI / VS Code hooks"
		if enforce {
			rep.Message += " (enforce mode: blocks matches from rules marked enforce=true)"
		}
	}
	return rep, err
}

func uninstallVSCode(path string) (InstallReport, error) {
	rep, err := uninstallCopilotAt(path, false)
	rep.Agent = AgentVSCode
	if err == nil && rep.Changed {
		rep.Message = "removed shared Copilot CLI / VS Code hooks"
	}
	return rep, err
}

func statusVSCode(path string) InstallReport {
	rep := statusCopilot(path)
	rep.Agent = AgentVSCode
	if rep.Installed {
		rep.Message = "shared Copilot CLI / VS Code hooks installed"
	}
	return rep
}
