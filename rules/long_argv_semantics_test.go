package rules_test

import (
	"strings"
	"testing"
)

func TestRulesPreserveLongArgvSemantics(t *testing.T) {
	eng := builtinEngine(t)
	longEnv := strings.Repeat("--env K=V ", 96)

	cases := []struct {
		name    string
		ruleID  string
		command string
		want    bool
	}{
		{
			name:    "unrelated long Docker argv",
			ruleID:  "tamper.agent_config_write",
			command: "docker run " + strings.Repeat("--env ~/.codex/hooks.json ", 96) + "ubuntu:24.04",
		},
		{
			name:    "PowerShell target after many switches",
			ruleID:  "tamper.agent_config_write",
			command: "Remove-Item " + strings.Repeat("-Force ", 128) + `$HOME\.codex\hooks.json`,
			want:    true,
		},
		{
			name:    "PowerShell positional destination before many switches",
			ruleID:  "tamper.agent_config_write",
			command: `Copy-Item C:\tmp\hooks.json C:\ProgramData\OpenAI\Codex\requirements.toml ` + strings.Repeat("-Force ", 128),
			want:    true,
		},
		{
			name:    "dangerous Docker option after long valid prefix",
			ruleID:  "privilege.container_host_escape",
			command: "docker run " + longEnv + "--privileged ubuntu:24.04",
			want:    true,
		},
		{
			name:    "dangerous Docker option after image",
			ruleID:  "privilege.container_host_escape",
			command: "docker run " + longEnv + "ubuntu:24.04 --privileged",
		},
		{
			name:    "dangerous-looking Docker option values",
			ruleID:  "privilege.container_host_escape",
			command: "docker run " + strings.Repeat("--env --privileged ", 96) + "ubuntu:24.04",
		},
		{
			name:    "run-like global option values before real subcommand",
			ruleID:  "privilege.container_host_escape",
			command: "docker " + strings.Repeat("--context run ", 64) + "run --privileged ubuntu:24.04",
			want:    true,
		},
		{
			name:    "long Docker run is not workload exec",
			ruleID:  "lateral.workload_exec",
			command: "docker run " + longEnv + "ubuntu:24.04",
		},
		{
			name:    "exec-like global option values before real remote exec",
			ruleID:  "lateral.workload_exec",
			command: "docker --host ssh://builder " + strings.Repeat("--context exec ", 64) + "exec workload sh",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, cmd(tc.command)), tc.ruleID)
			if got != tc.want {
				t.Fatalf("%s match = %t, want %t", tc.ruleID, got, tc.want)
			}
		})
	}
}
