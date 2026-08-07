package extract

import "testing"

func TestResultDiagnosticsAreBounded(t *testing.T) {
	var result Result
	for i := 1; i <= maxDiagnosticsPerArtifact*2; i++ {
		result.diag("artifact.jsonl", i, "malformed record")
	}
	result.diag("artifact.jsonl", 100, "unsupported record shape")
	if len(result.Diagnostics) != maxRepeatedDiagnostic+2 {
		t.Fatalf("diagnostics = %+v", result.Diagnostics)
	}
	if got := result.Diagnostics[len(result.Diagnostics)-2].Msg; got != "unsupported record shape" {
		t.Fatalf("distinct diagnostic was suppressed: %+v", result.Diagnostics)
	}
	last := result.Diagnostics[len(result.Diagnostics)-1]
	if last.Msg != "additional diagnostics suppressed" {
		t.Fatalf("last diagnostic = %+v", last)
	}
}

func TestResultDistinctDiagnosticsRespectTotalBound(t *testing.T) {
	var result Result
	for i := 0; i < maxDiagnosticsPerArtifact*2; i++ {
		result.diag("artifact.jsonl", i+1, string(rune('a'+i)))
	}
	if len(result.Diagnostics) != maxDiagnosticsPerArtifact {
		t.Fatalf("diagnostics = %d, want %d", len(result.Diagnostics), maxDiagnosticsPerArtifact)
	}
	if got := result.Diagnostics[len(result.Diagnostics)-1].Msg; got != "additional diagnostics suppressed" {
		t.Fatalf("last diagnostic = %q", got)
	}
}
