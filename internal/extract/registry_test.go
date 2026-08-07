package extract

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func TestForKnownAgent(t *testing.T) {
	ex, ok := For(model.AgentClaudeCode)
	if !ok {
		t.Fatal("claude-code should have a registered extractor")
	}
	if ex.Agent() != model.AgentClaudeCode {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentClaudeCode)
	}
}

func TestForGeminiCLI(t *testing.T) {
	ex, ok := For(model.AgentGeminiCLI)
	if !ok {
		t.Fatal("gemini-cli should have a registered extractor")
	}
	if ex.Agent() != model.AgentGeminiCLI {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentGeminiCLI)
	}
}

func TestForCodex(t *testing.T) {
	ex, ok := For(model.AgentCodex)
	if !ok {
		t.Fatal("codex should have a registered extractor")
	}
	if ex.Agent() != model.AgentCodex {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentCodex)
	}
}

func TestForCowork(t *testing.T) {
	ex, ok := For(model.AgentCowork)
	if !ok {
		t.Fatal("cowork should have a registered extractor")
	}
	if ex.Agent() != model.AgentCowork {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentCowork)
	}
}

func TestForCursor(t *testing.T) {
	ex, ok := For(model.AgentCursor)
	if !ok {
		t.Fatal("cursor should have a registered extractor")
	}
	if ex.Agent() != model.AgentCursor {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentCursor)
	}
}

func TestForWindsurf(t *testing.T) {
	ex, ok := For(model.AgentWindsurf)
	if !ok {
		t.Fatal("windsurf should have a registered extractor")
	}
	if ex.Agent() != model.AgentWindsurf {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentWindsurf)
	}
}

func TestForCopilot(t *testing.T) {
	ex, ok := For(model.AgentCopilot)
	if !ok {
		t.Fatal("copilot should have a registered extractor")
	}
	if ex.Agent() != model.AgentCopilot {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentCopilot)
	}
}

func TestForOpenCode(t *testing.T) {
	ex, ok := For(model.AgentOpenCode)
	if !ok {
		t.Fatal("opencode should have a registered extractor")
	}
	if ex.Agent() != model.AgentOpenCode {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentOpenCode)
	}
}

func TestForPi(t *testing.T) {
	ex, ok := For(model.AgentPi)
	if !ok {
		t.Fatal("pi should have a registered extractor")
	}
	if ex.Agent() != model.AgentPi {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentPi)
	}
}

func TestForKimiCode(t *testing.T) {
	ex, ok := For(model.AgentKimiCode)
	if !ok {
		t.Fatal("kimi-code should have a registered extractor")
	}
	if ex.Agent() != model.AgentKimiCode {
		t.Errorf("extractor Agent() = %q, want %q", ex.Agent(), model.AgentKimiCode)
	}
}

func TestForUnknownAgent(t *testing.T) {
	if _, ok := For("nonesuch"); ok {
		t.Error("unknown agent should not resolve to an extractor")
	}
}

// TestRegisteredAgentsAgreesWithFor asserts the two readers of the registry can
// never drift: every id RegisteredAgents reports must resolve through For, and
// each resolved extractor's own Agent() must equal the id it is keyed under (so a
// mis-filed registry entry — right extractor, wrong key — is caught here, not in
// production). This is the same-package agreement test that lets `auspex agents`
// trust extract.RegisteredAgents() as its drift-guard authority.
func TestRegisteredAgentsAgreesWithFor(t *testing.T) {
	ids := RegisteredAgents()
	if len(ids) != len(registry) {
		t.Fatalf("RegisteredAgents returned %d ids, registry has %d", len(ids), len(registry))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("RegisteredAgents returned duplicate id %q", id)
		}
		seen[id] = true
		ex, ok := For(id)
		if !ok {
			t.Errorf("RegisteredAgents reported %q but For does not resolve it", id)
			continue
		}
		if ex.Agent() != id {
			t.Errorf("registry key %q holds an extractor whose Agent() = %q", id, ex.Agent())
		}
	}
	// RegisteredAgents is sorted, so a caller can rely on deterministic order.
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Errorf("RegisteredAgents not sorted: %q before %q", ids[i-1], ids[i])
		}
	}
}
