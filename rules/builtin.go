// Package rules embeds Auspex's built-in rule catalog.
//
// The YAML files in this directory are ordinary Auspex rule files: the binary
// embeds them for default detection, and operators can read the same files when
// writing their own rules.
package rules

import "embed"

//go:embed */*.yaml
var FS embed.FS

// Dir is the directory within FS that holds the embedded rule files.
const Dir = "."
