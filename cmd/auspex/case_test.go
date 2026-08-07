package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCaseBuildVerifyRoundTrip is the end-to-end path an investigator runs:
// capture a scan's records to a file, bundle one case from them, verify the
// bundle, then prove tampering is caught.
func TestCaseBuildVerifyRoundTrip(t *testing.T) {
	transcript := writeTranscript(t, scanTranscript)
	records := filepath.Join(t.TempDir(), "records.ndjson")
	if _, errb, code := runCLI("scan", "--path", transcript, "--case-id", "c-1",
		"--emit", "all", "--output", "file", "--output-file", records); code != 0 {
		t.Fatalf("scan exit = %d (err=%s)", code, errb)
	}

	bundle := filepath.Join(t.TempDir(), "case.auspex")
	out, errb, code := runCLI("case", "build", "c-1", "--from", records, "--out", bundle)
	if code != 0 {
		t.Fatalf("build exit = %d (err=%s)", code, errb)
	}
	// The scan produces two findings citing two events of the transcript.
	if !strings.Contains(out, "2 findings, 2 events") {
		t.Fatalf("build summary = %q", out)
	}
	if !strings.Contains(out, "self-consistency only") {
		t.Fatalf("build output must state the integrity-not-authenticity scope: %q", out)
	}
	// Safe default: no evidence copies.
	if _, err := os.Lstat(filepath.Join(bundle, "evidence")); !os.IsNotExist(err) {
		t.Fatal("default bundle must not copy evidence files")
	}

	out, _, code = runCLI("case", "verify", bundle)
	if code != 0 || !strings.Contains(out, "bundle verified: case c-1") {
		t.Fatalf("verify exit = %d, out = %q", code, out)
	}

	// Tamper, then verify again: non-zero exit and a named problem.
	if err := os.WriteFile(filepath.Join(bundle, "findings.ndjson"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code = runCLI("case", "verify", bundle)
	if code != 1 || !strings.Contains(out, "FAILED verification") {
		t.Fatalf("tampered verify exit = %d, out = %q", code, out)
	}
}

func TestCaseBuildUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{"case"}, "usage:"},
		{"unknown subcommand", []string{"case", "publish"}, "unknown case subcommand"},
		{"missing case id", []string{"case", "build", "--from", "x.ndjson"}, "case id comes first"},
		{"missing from", []string{"case", "build", "c-1"}, "--from"},
		{"both evidence modes", []string{
			"case", "build", "c-1", "--from", "x.ndjson",
			"--include-raw-evidence", "--include-redacted-evidence",
		}, "mutually exclusive"},
		{"verify no dir", []string{"case", "verify"}, "usage: auspex case verify"},
		{"stray build arg", []string{"case", "build", "c-1", "--from", "x.ndjson", "extra"}, "unexpected argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errb, code := runCLI(tc.args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.Contains(errb, tc.want) {
				t.Fatalf("stderr = %q, want %q", errb, tc.want)
			}
		})
	}
}

func TestCaseNestedHelpExitsZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"build", []string{"case", "build", "--help"}, "auspex case build <case-id>"},
		{"verify", []string{"case", "verify", "--help"}, "usage: auspex case verify <DIR>"},
		{"help alias build", []string{"help", "case", "build"}, "auspex case build <case-id>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errb, code := runCLI(tc.args...)
			if code != 0 {
				t.Fatalf("exit = %d, stderr=%q", code, errb)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("stdout = %q, want %q", out, tc.want)
			}
		})
	}

	out, _, _ := runCLI("case", "build", "--help")
	for _, flag := range []string{"-from", "-include-raw-evidence", "-include-redacted-evidence", "-out"} {
		if !strings.Contains(out, flag) {
			t.Errorf("case build help missing %s: %q", flag, out)
		}
	}
}

func TestCaseBuildUnknownCaseIDFails(t *testing.T) {
	transcript := writeTranscript(t, scanTranscript)
	records := filepath.Join(t.TempDir(), "records.ndjson")
	if _, _, code := runCLI("scan", "--path", transcript, "--case-id", "c-1",
		"--output", "file", "--output-file", records); code != 0 {
		t.Fatal("scan failed")
	}
	bundle := filepath.Join(t.TempDir(), "case.auspex")
	_, errb, code := runCLI("case", "build", "c-other", "--from", records, "-o", bundle)
	if code != 1 || !strings.Contains(errb, "no findings") {
		t.Fatalf("exit = %d, stderr = %q", code, errb)
	}
}
