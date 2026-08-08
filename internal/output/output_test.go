package output

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func testFinding(id string) model.Finding {
	return model.Finding{
		SchemaVersion: model.SchemaVersion,
		FindingID:     id,
		DetectedAt:    "2026-07-23T18:00:00Z",
		RuleID:        "test.rule",
		RuleVersion:   "test",
		Severity:      model.SeverityLow,
		SourceAgent:   model.AgentUnknown,
		SourceType:    model.SourceArtifact,
		Title:         "Test finding",
		EvidenceRefs:  []model.Evidence{{ArtifactType: "test"}},
		CitedEventIDs: []string{"event-1"},
		Redacted:      false,
		Confidence:    model.ConfidenceHigh,
	}
}

func testEnforcement() model.EnforcementDecision {
	return model.EnforcementDecision{
		SchemaVersion:  model.SchemaVersion,
		DecisionID:     "enf-0123456789abcdef01234567",
		Timestamp:      "2026-07-23T18:00:00Z",
		Decision:       model.EnforcementDecisionNoOverride,
		Mode:           model.EnforcementModeMonitor,
		Reason:         model.EnforcementReasonMonitorMode,
		SourceAgent:    model.AgentCodex,
		SourceType:     model.SourceHook,
		ActionEventIDs: []string{"event-1"},
		FindingIDs:     []string{"finding-1"},
		RuleIDs:        []string{"test.rule"},
	}
}

func TestEmitFindingNDJSON(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run1")
	f := testFinding("fnd_01")
	f.RuleID = "secrets.agent_read_env"
	f.Severity = model.SeverityHigh
	f.Title = "Agent read .env file"
	f.Redacted = true
	if err := e.EmitFinding(f); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitFinding(f); err != nil {
		t.Fatal(err)
	}
	if s := e.Stats(); s.FindingsEmitted != 2 {
		t.Fatalf("FindingsEmitted = %d, want 2", s.FindingsEmitted)
	}
	lines := strings.Split(strings.TrimSpace(recs.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d", len(lines))
	}
	var got model.Finding
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("line is not valid JSON: %v", err)
	}
	if got.FindingID != "fnd_01" || got.Severity != model.SeverityHigh {
		t.Fatalf("decoded finding = %+v", got)
	}
	if diags.Len() != 0 {
		t.Fatalf("diagnostics writer should be empty, got %q", diags.String())
	}
}

func TestDiagnosticsCanShareRecordSink(t *testing.T) {
	var records bytes.Buffer
	e := NewWithSinkAndDiagnostics(nopCloseSink{&records}, "run1")
	e.Diag(DiagnosticWarn, "state unavailable")

	var got Diagnostic
	if err := json.Unmarshal(bytes.TrimSpace(records.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got.RecordType != RecordDiagnostic || got.RunID != "run1" || got.Message != "state unavailable" {
		t.Fatalf("diagnostic record = %+v", got)
	}
	if stats := e.Stats(); stats.Diagnostics != 1 || stats.RecordErrors != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	failed := NewWithSinkAndDiagnostics(nopCloseSink{failingRecordWriter{}}, "run2")
	failed.Diag(DiagnosticError, "delivery failed")
	if stats := failed.Stats(); stats.Diagnostics != 1 || stats.RecordErrors != 1 {
		t.Fatalf("failed diagnostic stats = %+v", stats)
	}
}

// TestConcurrentEmit asserts the emitter is safe under concurrent use and that
// every emitted finding lands as one standalone JSON line. Run with -race.
func TestConcurrentEmit(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run1")
	const (
		workers = 8
		per     = 50
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				_ = e.EmitFinding(testFinding("f"))
				e.Diag("info", "tick")
			}
		}()
	}
	wg.Wait()

	if s := e.Stats(); s.FindingsEmitted != workers*per || s.Diagnostics != workers*per {
		t.Fatalf("stats = %+v, want %d each", s, workers*per)
	}
	lines := strings.Split(strings.TrimSpace(recs.String()), "\n")
	if len(lines) != workers*per {
		t.Fatalf("got %d finding lines, want %d", len(lines), workers*per)
	}
	for _, ln := range lines {
		var f model.Finding
		if err := json.Unmarshal([]byte(ln), &f); err != nil {
			t.Fatalf("interleaved/garbled NDJSON line %q: %v", ln, err)
		}
	}
}

// Every record kind is stamped with the record_type/run_id/schema_version
// envelope and lands on its own line, and the per-kind counters advance.
func TestEmitEnvelopeAllRecordKinds(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run-env")
	if err := e.EmitEvent(model.Event{SchemaVersion: model.SchemaVersion, EventID: "ev1", EventType: model.EventCommandExec}); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitEnforcement(testEnforcement()); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitIndicator(Indicator{Type: IndicatorDomain, Value: "evil.example", Count: 3}); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitSummary(ScanSummary{Status: StatusComplete, ArtifactsScanned: 1}); err != nil {
		t.Fatal(err)
	}
	if s := e.Stats(); s.EventsEmitted != 1 || s.IndicatorsEmitted != 1 {
		t.Fatalf("stats = %+v, want 1 event / 1 indicator", s)
	}

	lines := strings.Split(strings.TrimSpace(recs.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d records, want 4", len(lines))
	}
	wantTypes := []string{RecordEvent, RecordEnforcement, RecordIndicator, RecordScanSummary}
	for i, ln := range lines {
		var env struct {
			RecordType    string   `json:"record_type"`
			RunID         string   `json:"run_id"`
			SchemaVersion string   `json:"schema_version"`
			Endpoint      Endpoint `json:"endpoint"`
		}
		if err := json.Unmarshal([]byte(ln), &env); err != nil {
			t.Fatalf("record %d not JSON: %v", i, err)
		}
		if env.RecordType != wantTypes[i] {
			t.Errorf("record %d record_type = %q, want %q", i, env.RecordType, wantTypes[i])
		}
		if env.RunID != "run-env" {
			t.Errorf("record %d run_id = %q, want run-env", i, env.RunID)
		}
		if env.SchemaVersion != model.SchemaVersion {
			t.Errorf("record %d schema_version = %q, want %q", i, env.SchemaVersion, model.SchemaVersion)
		}
		if env.Endpoint.Hostname == "" || env.Endpoint.OS == "" || env.Endpoint.Arch == "" {
			t.Errorf("record %d missing endpoint envelope: %+v", i, env)
		}
	}
	if diags.Len() != 0 {
		t.Fatalf("diagnostics writer should be empty, got %q", diags.String())
	}
}

type failingRecordWriter struct{}

func (failingRecordWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestEmitStatsCountRecordErrors(t *testing.T) {
	var diags bytes.Buffer
	e := New(failingRecordWriter{}, &diags, "run-fail")
	err := e.EmitEvent(model.Event{SchemaVersion: model.SchemaVersion, EventID: "ev1", EventType: model.EventCommandExec})
	if err == nil {
		t.Fatal("EmitEvent error = nil, want write error")
	}
	s := e.Stats()
	if s.RecordErrors != 1 {
		t.Fatalf("RecordErrors = %d, want 1", s.RecordErrors)
	}
	if s.EventsEmitted != 0 {
		t.Fatalf("EventsEmitted = %d, want 0 after failed write", s.EventsEmitted)
	}
	if diags.Len() != 0 {
		t.Fatalf("emitter must not write diagnostics on its own, got %q", diags.String())
	}
}

func TestEmitStampsEmptySchemaVersion(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run-schema")
	ev := model.Event{
		EventID:     "ev-empty-schema",
		SourceAgent: model.AgentCodex,
		SourceType:  model.SourceArtifact,
		EventType:   model.EventCommandExec,
		Command:     "true",
		Confidence:  model.ConfidenceHigh,
		Evidence:    model.Evidence{ArtifactType: "test"},
	}
	if err := e.EmitEvent(ev); err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(recs.String())), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != model.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, model.SchemaVersion)
	}
}

func TestDiagSeparateStream(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run1")
	e.Diag(DiagnosticWarn, "gemini parser is best-effort")
	if recs.Len() != 0 {
		t.Fatalf("findings stream polluted by diagnostic: %q", recs.String())
	}
	var d Diagnostic
	if err := json.Unmarshal([]byte(strings.TrimSpace(diags.String())), &d); err != nil {
		t.Fatal(err)
	}
	if d.Level != "warn" || d.RunID != "run1" || d.RecordType != "diagnostic" {
		t.Fatalf("diagnostic = %+v", d)
	}
	if d.Endpoint.Hostname == "" || d.Endpoint.OS == "" || d.Endpoint.Arch == "" {
		t.Fatalf("diagnostic missing endpoint envelope: %+v", d)
	}
}

func TestDiagNormalizesUnknownLevel(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run1")
	e.Diag("debug", "skipped noisy record")
	if recs.Len() != 0 {
		t.Fatalf("records stream polluted by diagnostic: %q", recs.String())
	}
	var d Diagnostic
	if err := json.Unmarshal([]byte(strings.TrimSpace(diags.String())), &d); err != nil {
		t.Fatal(err)
	}
	if d.Level != DiagnosticInfo {
		t.Fatalf("diagnostic level = %q, want %q", d.Level, DiagnosticInfo)
	}
}

func TestDeviceIDFromEnvironment(t *testing.T) {
	t.Setenv(EnvDeviceID, " fleet-device-42 ")

	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run-device")
	if err := e.EmitEvent(model.Event{SchemaVersion: model.SchemaVersion, EventID: "ev1", EventType: model.EventCommandExec}); err != nil {
		t.Fatal(err)
	}
	e.Diag("info", "runtime ready")

	var rec struct {
		Endpoint Endpoint `json:"endpoint"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(recs.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Endpoint.DeviceID != "fleet-device-42" {
		t.Fatalf("record endpoint.device_id = %q, want fleet-device-42", rec.Endpoint.DeviceID)
	}

	var diag Diagnostic
	if err := json.Unmarshal([]byte(strings.TrimSpace(diags.String())), &diag); err != nil {
		t.Fatal(err)
	}
	if diag.Endpoint.DeviceID != "fleet-device-42" {
		t.Fatalf("diagnostic endpoint.device_id = %q, want fleet-device-42", diag.Endpoint.DeviceID)
	}
}

func TestDeviceIDTrimsWhitespace(t *testing.T) {
	t.Setenv(EnvDeviceID, " \tfleet-device-42\n")
	if got := deviceID(); got != "fleet-device-42" {
		t.Fatalf("deviceID() = %q, want fleet-device-42", got)
	}

	t.Setenv(EnvDeviceID, " \t\n")
	if got := deviceID(); got != "" {
		t.Fatalf("deviceID() = %q, want empty", got)
	}
}

func TestUserEnvelopeOnRecordsAndDiagnostics(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run-user")
	e.endpoint.Username = "dev"
	e.endpoint.UID = "501"
	if err := e.EmitSummary(ScanSummary{Status: StatusComplete}); err != nil {
		t.Fatal(err)
	}
	e.Diag(DiagnosticInfo, "ready")

	for label, raw := range map[string]string{"record": recs.String(), "diagnostic": diags.String()} {
		var envelope struct {
			Endpoint Endpoint `json:"endpoint"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &envelope); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if envelope.Endpoint.Username != "dev" || envelope.Endpoint.UID != "501" {
			t.Fatalf("%s user envelope = %+v", label, envelope)
		}
	}
}

// TestRulesetDigestAbsentWhenUnset pins the "absent means no catalog was
// resolved" contract: an emitter that never learned a digest must not invent
// one, and the stderr diagnostic path must stay byte-identical to before the
// field existed. A sentinel value here would read as an attestation.
func TestRulesetDigestAbsentWhenUnset(t *testing.T) {
	var recs, diags bytes.Buffer
	e := New(&recs, &diags, "run-nodigest")
	if err := e.EmitSummary(ScanSummary{Status: StatusComplete}); err != nil {
		t.Fatal(err)
	}
	e.Diag(DiagnosticInfo, "ready")

	for label, raw := range map[string]string{"record": recs.String(), "diagnostic": diags.String()} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &fields); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if _, ok := fields["ruleset_digest"]; ok {
			t.Fatalf("%s carries ruleset_digest with no catalog resolved: %s", label, raw)
		}
	}
}

// TestRulesetDigestStampedOnEveryRecord: once set, the digest rides the same
// envelope as run_id, including diagnostics routed into the record sink.
func TestRulesetDigestStampedOnEveryRecord(t *testing.T) {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	var recs bytes.Buffer
	e := NewWithSinkAndDiagnostics(nopCloseSink{&recs}, "run-digest")
	e.SetRulesetDigest(digest)
	if err := e.EmitFinding(testFinding("finding-1")); err != nil {
		t.Fatal(err)
	}
	e.Diag(DiagnosticWarn, "operator rules replaced built-in rule ids: secrets.agent_read_env")

	lines := strings.Split(strings.TrimSpace(recs.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2", len(lines))
	}
	for _, line := range lines {
		var record struct {
			RulesetDigest string `json:"ruleset_digest"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.RulesetDigest != digest {
			t.Fatalf("ruleset_digest = %q, want %q\n%s", record.RulesetDigest, digest, line)
		}
	}
}
