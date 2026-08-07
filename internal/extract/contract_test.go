package extract

import (
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// TestEmittedEventsSatisfyContract runs every parser over its full fixture and
// asserts each emitted event passes model.Event.Validate(). This is the proof
// that the event_type→field co-occurrence contract (model.eventFields) matches
// what the parsers actually emit: if a parser sets a value-bearing field the
// contract does not allow for that event_type, Validate fails here. The full
// profile is used so reasoning and session-context fields are exercised too.
//
// If this fails, the allow-list is wrong — fix model.eventFields to match real
// parser output; never loosen Validate to a no-op.
func TestEmittedEventsSatisfyContract(t *testing.T) {
	pi, err := (PiExtractor{}).Extract(strings.NewReader(piSessionFixture), Source{Profile: ProfileFull})
	if err != nil {
		t.Fatalf("extract Pi fixture: %v", err)
	}
	kimi, err := (KimiCodeExtractor{}).Extract(strings.NewReader(kimiWireFixture), Source{Profile: ProfileFull})
	if err != nil {
		t.Fatalf("extract Kimi fixture: %v", err)
	}

	cases := []struct {
		name   string
		agent  string
		events []model.Event
	}{
		{"claude", model.AgentClaudeCode, extractFixtureProfile(t, claudeFixture, ProfileFull).Events},
		{"cowork", model.AgentCowork, extractCowork(t, coworkFixture, ProfileFull).Events},
		{"codex", model.AgentCodex, extractCodexProfile(t, codexFixture, ProfileFull).Events},
		{"gemini", model.AgentGeminiCLI, extractGemini(t, geminiArrayFixture).Events},
		{"gemini-session", model.AgentGeminiCLI, extractGeminiSession(t, geminiSessionFixture, ProfileFull).Events},
		{"cursor", model.AgentCursor, extractCursor(t, cursorFixture, ProfileFull).Events},
		{"windsurf", model.AgentWindsurf, extractWindsurf(t, windsurfFixture, ProfileFull).Events},
		{"copilot", model.AgentCopilot, extractCopilot(t, copilotFixture, ProfileFull).Events},
		{"opencode", model.AgentOpenCode, extractOpenCodeProfile(t, `{"type":"tool","callID":"c1","tool":"bash","state":{"status":"error","input":{"command":"go test ./..."},"error":"tests failed"}}`, ProfileFull).Events},
		{"openclaw", model.AgentOpenClaw, extractOpenClaw(t, withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"go test ./..."}}]}}`)).Events},
		{"pi", model.AgentPi, pi.Events},
		{"kimi-code", model.AgentKimiCode, kimi.Events},
	}
	covered := make(map[string]bool, len(cases))
	for _, c := range cases {
		covered[c.agent] = true
		t.Run(c.name, func(t *testing.T) {
			if len(c.events) == 0 {
				t.Fatalf("%s fixture produced no events", c.name)
			}
			for _, ev := range c.events {
				if ev.SourceAgent != c.agent {
					t.Errorf("%s: source_agent = %q, want %q", c.name, ev.SourceAgent, c.agent)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("%s: emitted event violates contract: %v\n  event=%+v", c.name, err, ev)
				}
			}
		})
	}
	for _, agent := range RegisteredAgents() {
		if !covered[agent] {
			t.Errorf("registered parser %q has no event-contract fixture", agent)
		}
	}
}
