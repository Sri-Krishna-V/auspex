package hook

import (
	"path/filepath"
	"testing"
)

// Every backend in this test writes a native command-hook timeout. A zero value
// is not a harmless default: Claude Code and Codex can otherwise wait ten
// minutes for a stuck callback. Keep the event catalogs explicit so newly added
// lifecycle hooks cannot silently inherit an upstream deadline.
func TestTimeoutCapableHookEventsAreExplicitlyBounded(t *testing.T) {
	type eventTimeout struct {
		agent   string
		event   string
		timeout int
	}
	var events []eventTimeout
	for _, ev := range claudeHookEvents {
		events = append(events, eventTimeout{AgentClaude, ev.settingsKey, ev.timeout})
	}
	for _, ev := range codexHookEvents {
		events = append(events, eventTimeout{AgentCodex, ev.settingsKey, ev.timeout})
	}
	for _, ev := range copilotHookEvents {
		events = append(events, eventTimeout{AgentCopilot, ev.event, ev.timeout})
	}
	for _, ev := range factoryHookEvents {
		events = append(events, eventTimeout{AgentFactory, ev.settingsKey, ev.timeout})
	}
	for _, ev := range devinHookEvents {
		events = append(events, eventTimeout{AgentDevin, ev.eventKey, ev.timeout})
	}
	for _, ev := range antigravityHookEvents {
		events = append(events, eventTimeout{AgentAntigravity, ev.eventKey, ev.timeout})
	}
	for _, ev := range grokHookEvents {
		events = append(events, eventTimeout{AgentGrok, ev.eventKey, ev.timeout})
	}
	for _, ev := range hermesHookEvents {
		events = append(events, eventTimeout{AgentHermes, ev.eventKey, ev.timeout})
	}
	for _, ev := range geminiHookEvents {
		if ev.timeoutMs <= 0 {
			t.Errorf("%s event %s has no explicit timeout", AgentGemini, ev.settingsKey)
		}
	}
	for _, ev := range kimiHookEvents {
		if ev.timeout <= 0 {
			t.Errorf("%s event %s has no explicit timeout", AgentKimi, ev.event)
		}
	}
	for _, ev := range qwenHookEvents {
		if ev.timeoutMs <= 0 {
			t.Errorf("%s event %s has no explicit timeout", AgentQwen, ev.settingsKey)
		}
	}
	for _, ev := range auggieHookEvents {
		if ev.timeoutMs <= 0 {
			t.Errorf("%s event %s has no explicit timeout", AgentAuggie, ev.settingsKey)
		}
	}
	for _, ev := range kiroHookEvents {
		if ev.timeout <= 0 {
			t.Errorf("%s event %s has no explicit timeout", AgentKiro, ev.trigger)
		}
	}

	for _, ev := range events {
		if ev.timeout <= 0 {
			t.Errorf("%s event %s has no explicit timeout", ev.agent, ev.event)
		}
	}
}

func TestClaudeAndCodexInstallsSerializeEveryTimeout(t *testing.T) {
	tests := []struct {
		agent  string
		events map[string]int
	}{
		{agent: AgentClaude, events: claudeTimeouts()},
		{agent: AgentCodex, events: codexTimeouts()},
	}
	for _, tt := range tests {
		t.Run(tt.agent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			if _, err := Install(tt.agent, path, auspexBinary, "", false); err != nil {
				t.Fatalf("Install: %v", err)
			}
			hooks := readHooks(t, path)
			for event, want := range tt.events {
				var got int
				for _, group := range hooks[event] {
					for _, ref := range group.Hooks {
						if isAuspexHookRef(ref) {
							got = ref.Timeout
						}
					}
				}
				if got != want {
					t.Errorf("event %s timeout = %d, want %d", event, got, want)
				}
			}
		})
	}
}

func claudeTimeouts() map[string]int {
	out := make(map[string]int, len(claudeHookEvents))
	for _, ev := range claudeHookEvents {
		out[ev.settingsKey] = ev.timeout
	}
	return out
}

func codexTimeouts() map[string]int {
	out := make(map[string]int, len(codexHookEvents))
	for _, ev := range codexHookEvents {
		out[ev.settingsKey] = ev.timeout
	}
	return out
}
