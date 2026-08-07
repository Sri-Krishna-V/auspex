//go:build windows

package hook

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func systemPowerShellPath() string {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil || systemDir == "" {
		// Keep executable lookup out of the working directory even if the API
		// unexpectedly fails. Standard supported installations use this path.
		systemDir = `C:\Windows\System32`
	}
	return filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe")
}
