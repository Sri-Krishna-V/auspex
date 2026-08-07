// Package version exposes the build version string. Version is overridden at
// release time via -ldflags; it defaults to "dev" for local builds.
package version

import "runtime/debug"

// Version is set at build time with:
//
//	-ldflags "-X github.com/Sri-Krishna-V/auspex/internal/version.Version=vX.Y.Z"
var Version = "dev"

// String returns the resolved version. When built from source without an
// injected version, it falls back to the VCS revision recorded by the Go
// toolchain, then to "dev".
func String() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				rev := s.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
				return "dev+" + rev
			}
		}
	}
	return Version
}
