package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/rule"
)

// rulesetDigestShape is the pattern published in every record schema. Asserting
// it here keeps the emitted value and the contract from drifting apart.
var rulesetDigestShape = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// stubReadEnvRule keeps the built-in's id and its author-declared version while
// neutering the expression: the lobotomy the digest exists to expose. Nothing
// about the decoded rule distinguishes it from the real one.
const stubReadEnvRule = `id: secrets.agent_read_env
version: "1.3"
enabled: true
title: .env file access
severity: medium
expr: 'false'
`

func writeRulesDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stub.yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	return dir
}

// oneRulesetDigest asserts every record on stdout carries the same well-formed
// ruleset_digest and returns it. A stream whose records disagree would let a
// receiver attribute a finding to the wrong catalog.
func oneRulesetDigest(t *testing.T, out string) string {
	t.Helper()
	var digests []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var record struct {
			RulesetDigest string `json:"ruleset_digest"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		digests = append(digests, record.RulesetDigest)
	}
	if len(digests) == 0 {
		t.Fatal("no records on stdout")
	}
	for _, digest := range digests {
		if !rulesetDigestShape.MatchString(digest) {
			t.Fatalf("ruleset_digest = %q, want the published sha256: shape", digest)
		}
		if digest != digests[0] {
			t.Fatalf("records disagree on ruleset_digest: %q vs %q", digest, digests[0])
		}
	}
	return digests[0]
}

func testSources() []rule.Source {
	return []rule.Source{
		{Path: "z/second.yaml", Rules: []rule.Rule{{ID: "b.two"}}, Digest: strings.Repeat("b", 64)},
		{Path: "a/first.yaml", Rules: []rule.Rule{{ID: "a.one"}}, Digest: strings.Repeat("a", 64)},
	}
}

// TestRulesetDigestStableAcrossRuns is the guard against a future map iteration
// creeping into the fold and silently randomizing the digest per process — a
// failure that would make fleet comparison useless while looking healthy. It
// also pins the two inputs that must not participate: catalog order and the
// operator's local file paths.
func TestRulesetDigestStableAcrossRuns(t *testing.T) {
	sources := testSources()
	want := rulesetDigest(sources, false)
	if !rulesetDigestShape.MatchString(want) {
		t.Fatalf("digest = %q, want the published sha256: shape", want)
	}
	if got := rulesetDigest(sources, false); got != want {
		t.Fatalf("digest is not deterministic: %q then %q", want, got)
	}

	reordered := []rule.Source{sources[1], sources[0]}
	if got := rulesetDigest(reordered, false); got != want {
		t.Fatalf("digest changed with catalog order: %q, want %q", got, want)
	}

	// Paths carry the operator's local directory; two endpoints running the
	// same catalog from different directories must still agree.
	relocated := testSources()
	relocated[0].Path = "/opt/elsewhere/second.yaml"
	if got := rulesetDigest(relocated, false); got != want {
		t.Fatalf("digest changed with source path: %q, want %q", got, want)
	}

	if got := rulesetDigest(sources, true); got == want {
		t.Fatal("--no-builtin-rules must not fold to the same digest as a built-in catalog")
	}

	// Same again end to end: two scans of the same tree must agree.
	p := writeTranscript(t, scanTranscript)
	first, _, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("first scan exit = %d", code)
	}
	second, _, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("second scan exit = %d", code)
	}
	if a, b := oneRulesetDigest(t, first), oneRulesetDigest(t, second); a != b {
		t.Fatalf("scan digest varies between runs: %q vs %q", a, b)
	}
}

// TestRulesetDigestChangesWhenBuiltinIsEclipsed is the threat test: an operator
// directory that replaces a built-in with a same-id, same-version stub must not
// produce a stream that is indistinguishable from the compliant one.
func TestRulesetDigestChangesWhenBuiltinIsEclipsed(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	compliant, _, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("built-in scan exit = %d", code)
	}
	lobotomized, _, code := runCLI("scan", "--path", p, "--rules-dir", writeRulesDir(t, stubReadEnvRule))
	if code != 0 {
		t.Fatalf("overlaid scan exit = %d", code)
	}
	if a, b := oneRulesetDigest(t, compliant), oneRulesetDigest(t, lobotomized); a == b {
		t.Fatalf("a replaced built-in reported the unchanged digest %q", a)
	}
}

// TestEclipseDiagnosticNamesReplacedBuiltin: the digest says the catalog is not
// the shipped one, but only the diagnostic says which detection stopped running.
func TestEclipseDiagnosticNamesReplacedBuiltin(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	_, errb, code := runCLI("scan", "--path", p, "--rules-dir", writeRulesDir(t, stubReadEnvRule))
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errb)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(errb), "\n") {
		if line == "" {
			continue
		}
		var diag struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(line), &diag); err != nil {
			t.Fatalf("stderr line not JSON: %v\n%s", err, line)
		}
		if strings.Contains(diag.Message, "operator rules replaced built-in rule ids") {
			if diag.Level != "warn" {
				t.Fatalf("eclipse diagnostic level = %q, want warn", diag.Level)
			}
			if !strings.Contains(diag.Message, "secrets.agent_read_env") {
				t.Fatalf("eclipse diagnostic does not name the replaced id: %q", diag.Message)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("replacing a shipped rule produced no eclipse diagnostic: %s", errb)
	}
}

// TestRulesetDigestAbsentForEventOnlyScan: an event-only run resolves no
// catalog, so it must claim none. Absence is the honest answer; a value here
// would attest rules that never evaluated anything.
func TestRulesetDigestAbsentForEventOnlyScan(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		if _, ok := fields["ruleset_digest"]; ok {
			t.Fatalf("event-only run attested a catalog it never compiled: %s", line)
		}
	}
}
