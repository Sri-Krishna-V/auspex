package main

import (
	"fmt"
	"io"

	"github.com/Sri-Krishna-V/auspex/internal/model"
	"github.com/Sri-Krishna-V/auspex/internal/version"
)

// versionString formats the tool name, build version, and schema version.
func versionString() string {
	return fmt.Sprintf("%s %s (schema %s)", model.ToolName, version.String(), model.SchemaVersion)
}

func versionUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: auspex version")
	fmt.Fprintln(w, "\nPrint the tool version and record schema version.")
}
