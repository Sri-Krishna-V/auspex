package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const coverageHookPayload = `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"cat .env"}}`

// decodeAgentRows runs `auspex agents --all --format json` and decodes the
// report, which is what a machine consumer of the OBSERVED column actually
// reads.
func decodeAgentRows(t *testing.T) map[string]agentRow {
	t.Helper()
	out, errb, code := runCLI("agents", "--all", "--format", "json")
	if code != 0 {
		t.Fatalf("agents exit = %d, want 0 (stderr=%s)", code, errb)
	}
	var rows []agentRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("decode agents json: %v\n%s", err, out)
	}
	if len(rows) == 0 {
		t.Fatal("agents --all returned no rows")
	}
	byName := make(map[string]agentRow, len(rows))
	for _, r := range rows {
		byName[r.Agent] = r
	}
	return byName
}

// TestCoverageLedgerStampsOnlyTheAgentThatRan is the feature end to end: a
// machine that has never run the hook reports "never" for every agent, and one
// hook callback moves exactly one row. The callback selects --emit events,
// which is the path that opens no state database of its own — the stamp has to
// open one, and that is the case most likely to silently do nothing.
func TestCoverageLedgerStampsOnlyTheAgentThatRan(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	before := decodeAgentRows(t)
	for name, r := range before {
		if r.Observed != observedNever {
			t.Errorf("fresh machine: %s observed = %q, want %q", name, r.Observed, observedNever)
		}
	}

	fired := time.Now().UTC()
	if _, errb, code := runCLIStdin(coverageHookPayload,
		"hook", "pre-tool", "--agent", "claude", "--emit", "events"); code != 0 {
		t.Fatalf("hook exit = %d, want 0 (stderr=%s)", code, errb)
	}

	after := decodeAgentRows(t)
	claude, ok := after["Claude Code"]
	if !ok {
		t.Fatal("no Claude Code row after the hook ran")
	}
	stamp, err := time.Parse(time.RFC3339, claude.Observed)
	if err != nil {
		t.Fatalf("Claude Code observed = %q, want an RFC3339 timestamp: %v", claude.Observed, err)
	}
	// A minute of slack absorbs the second-granularity truncation and a slow
	// test host without letting a wildly wrong clock through.
	if stamp.Before(fired.Add(-time.Minute)) || stamp.After(fired.Add(time.Minute)) {
		t.Errorf("Claude Code observed = %v, want within a minute of %v", stamp, fired)
	}
	// A stamp alone keeps the row in the default (present-only) inventory.
	if !claude.Present {
		t.Error("an agent auspex has demonstrably run for should be present in the default view")
	}
	for name, r := range after {
		if name != "Claude Code" && r.Observed != observedNever {
			t.Errorf("%s observed = %q after only claude ran, want %q", name, r.Observed, observedNever)
		}
	}
}

// TestCoverageLedgerStampsDespiteUndecodablePayload pins the semantics of the
// column against its most tempting misreading. OBSERVED answers "did auspex's
// hook run here", not "did it understand what it saw": a callback whose body
// fails to decode still ran, still fails open, and still counts as coverage.
// Withholding the stamp here would make a machine running auspex on every
// callback look unmonitored.
func TestCoverageLedgerStampsDespiteUndecodablePayload(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if _, errb, code := runCLIStdin("not json at all",
		"hook", "post-tool", "--agent", "claude", "--emit", "events"); code != 0 {
		t.Fatalf("hook exit = %d, want fail-open 0 (stderr=%s)", code, errb)
	}
	claude := decodeAgentRows(t)["Claude Code"]
	if claude.Observed == observedNever || claude.Observed == observedUnknown {
		t.Errorf("observed = %q after an undecodable payload, want a timestamp", claude.Observed)
	}
}

// TestAgentsReportsNeverWithoutCreatingStateDB guards the report-only posture:
// reading coverage must not bring the state database into existence, or
// `auspex agents` would write to a machine it claims only to inspect.
func TestAgentsReportsNeverWithoutCreatingStateDB(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	if _, _, code := runCLI("agents", "--all"); code != 0 {
		t.Fatalf("agents exit = %d, want 0", code)
	}
	if stamps, readable := agentCoverage(home); !readable || len(stamps) != 0 {
		t.Fatalf("agentCoverage = (%v, %v), want an empty readable ledger", stamps, readable)
	}
	if _, err := os.Stat(hookStateDBPath(home)); err == nil {
		t.Errorf("agents created %s; the report must write nothing", hookStateDBPath(home))
	}
}

// TestCoverageLedgerFollowsAgentReattribution pins the ledger key to the agent
// the events themselves name. A Copilot callback carrying a VS Code payload is
// already re-attributed to VS Code everywhere else; stamping the raw --agent
// flag would leave the VS Code row reading "never" for callbacks auspex
// demonstrably handled for it.
func TestCoverageLedgerFollowsAgentReattribution(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	payload := `{"hook_event_name":"PreToolUse","tool_name":"runTerminalCommand","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`
	if _, errb, code := runCLIStdin(payload,
		"hook", "pre-tool", "--agent", "copilot", "--emit", "events"); code != 0 {
		t.Fatalf("hook exit = %d, want 0 (stderr=%s)", code, errb)
	}

	rows := decodeAgentRows(t)
	if got := rows["VS Code Copilot Chat"].Observed; !isObservedStamp(got) {
		t.Errorf("VS Code Copilot Chat observed = %q, want a timestamp", got)
	}
	if got := rows["GitHub Copilot CLI"].Observed; got != observedNever {
		t.Errorf("GitHub Copilot CLI observed = %q, want %q — the payload named VS Code", got, observedNever)
	}
}

// TestAgentsReportsUnknownWhenLedgerUnreadable is the honest-failure test: a
// ledger auspex cannot read must never print as one holding nothing. Agents
// with no hook backend still read "never", because no readability question
// applies to a key nothing can write.
func TestAgentsReportsUnknownWhenLedgerUnreadable(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	path := hookStateDBPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("this is not a bolt database"), 0o600); err != nil {
		t.Fatalf("write corrupt state db: %v", err)
	}

	rows := decodeAgentRows(t)
	if got := rows["Claude Code"].Observed; got != observedUnknown {
		t.Errorf("Claude Code observed = %q with an unreadable ledger, want %q", got, observedUnknown)
	}
	if got := rows["Claude Cowork"].Observed; got != observedNever {
		t.Errorf("Claude Cowork (no hook backend) observed = %q, want %q", got, observedNever)
	}
}

// TestAgentsUsageCarriesObservedCaveat keeps the wording that stops "never"
// from being read as "the sensor is dead". The caveat is the deliverable of
// this feature; the column is only its carrier.
func TestAgentsUsageCarriesObservedCaveat(t *testing.T) {
	_, errb, code := runCLI("agents", "--help")
	if code != 0 {
		t.Fatalf("agents --help exit = %d, want 0", code)
	}
	usage := strings.Join(strings.Fields(errb), " ")
	for _, want := range []string{
		`OBSERVED is the last time auspex's hook actually ran for that agent on this machine.`,
		`"never" means no hook execution was recorded here — not that the agent never ran, and not that nothing happened.`,
		`Agents seen only by at-rest scanning never stamp this column.`,
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("agents usage is missing the OBSERVED caveat sentence:\n%s\n\nusage:\n%s", want, errb)
		}
	}
}
