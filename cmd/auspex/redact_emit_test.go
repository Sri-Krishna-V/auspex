package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// Secret canaries planted into a transcript's command, file_path, url, and
// prompt/content fields. None may appear in any emitted output: redaction runs
// on every emission path (event sink + timeline), not just findings.
const (
	canaryAWS    = "AKIAIOSFODNN7EXAMPLE"
	canaryOpenAI = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	canarySig    = "deadbeefcafefeed1234567890"
)

// redactCanaryTranscript plants a distinct secret in each redacted field:
//   - Bash command carries an AWS key,
//   - Read file_path carries an OpenAI key,
//   - WebFetch url carries a presigned-URL signature,
//   - the user prompt (-> content_preview) carries a private key header.
const redactCanaryTranscript = `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-06-02T10:00:00Z","cwd":"/home/dev/proj","message":{"role":"user","content":"here is a secret -----BEGIN RSA PRIVATE KEY----- abc"}}
{"type":"assistant","uuid":"a1","sessionId":"s1","timestamp":"2026-06-02T10:00:01Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cat .env && aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"}},{"type":"tool_use","id":"t2","name":"Read","input":{"file_path":"/home/dev/keys/sk-abcdefghijklmnopqrstuvwxyz0123456789"}},{"type":"tool_use","id":"t3","name":"WebFetch","input":{"url":"https://s3.example/obj?X-Amz-Signature=deadbeefcafefeed1234567890","prompt":"grab"}}]}}`

// assertNoCanaries fails if any planted secret survives in out.
func assertNoCanaries(t *testing.T, label, out string) {
	t.Helper()
	for _, c := range []string{canaryAWS, canaryOpenAI, canarySig, "PRIVATE KEY-----"} {
		if strings.Contains(out, c) {
			t.Errorf("%s leaked canary %q:\n%s", label, c, out)
		}
	}
}

// TestScanEmitEventsRedactsCanaries proves `scan --emit events` never leaks a
// planted secret in command/file_path/url/content_preview.
func TestScanEmitEventsRedactsCanaries(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	// Sanity: the events stream is present (the typed url field is emitted, masked).
	if !strings.Contains(out, `"event_type":"command.exec"`) {
		t.Fatalf("no events emitted:\n%s", out)
	}
	assertNoCanaries(t, "scan --emit events", out)
}

// TestScanEmitAllRedactsCanaries proves `scan --emit all` (events + findings +
// indicators) never leaks a planted secret on any record kind.
func TestScanEmitAllRedactsCanaries(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "all")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	assertNoCanaries(t, "scan --emit all", out)
}

func TestScanEmitEventsKeepsProjectPath(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"project_path":"/home/dev/proj"`) {
		t.Fatalf("scan --emit events missing readable project path:\n%s", out)
	}
}

func TestScanEmitAllKeepsProjectPath(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "all")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"project_path":"/home/dev/proj"`) {
		t.Fatalf("scan --emit all missing readable project path:\n%s", out)
	}
}

// TestTimelineJSONRedactsCanaries proves `timeline --format json` never leaks a
// planted secret: it marshals raw model.Events, so it must redact on emission.
func TestTimelineJSONRedactsCanaries(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("timeline", "--path", p, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "command.exec") {
		t.Fatalf("no timeline events:\n%s", out)
	}
	assertNoCanaries(t, "timeline --format json", out)
}

func TestTimelineJSONKeepsProjectPath(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("timeline", "--path", p, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"project_path": "/home/dev/proj"`) {
		t.Fatalf("timeline --format json missing readable project path:\n%s", out)
	}
}

// TestTimelineTextRedactsCanaries proves the default `timeline` text view never
// leaks a planted secret in its stepDetail column.
func TestTimelineTextRedactsCanaries(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("timeline", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "command.exec") {
		t.Fatalf("no timeline steps:\n%s", out)
	}
	assertNoCanaries(t, "timeline text", out)
}

func TestTimelineTextKeepsProjectPath(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("timeline", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "project: /home/dev/proj") {
		t.Fatalf("timeline text missing readable project path:\n%s", out)
	}
}

// TestCollectEmitEventsRedactsCanaries proves the OTLP receiver path (collect
// --emit events|all) shares the same emission guard: a planted secret value in a
// command, file path, or url attribute never reaches an emitted event/finding.
// collect routes events through the same output.Emitter.EmitEvent as scan.
func TestCollectEmitEventsRedactsCanaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		sel  emitSelection
	}{
		{"events", emitSelection{events: true}},
		{"all", emitSelection{events: true, findings: true, indicators: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var records, diags bytes.Buffer
			c := newTestCollector(t, &records, &diags, tc.sel)
			body := buildOTLPLogs("claude-code", []map[string]string{
				{"process.command": "aws configure set aws_access_key_id " + canaryAWS, "session.id": "s1"},
				{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/home/dev/keys/" + canaryOpenAI, "session.id": "s1"},
				{"url.full": "https://s3.example/obj?X-Amz-Signature=" + canarySig, "session.id": "s1"},
			})
			rr := postLogs(t, c, body, "application/x-protobuf")
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
			}
			out := records.String()
			if !strings.Contains(out, `"record_type":"event"`) {
				t.Fatalf("no events emitted:\n%s", out)
			}
			assertNoCanaries(t, "collect --emit "+tc.name, out)
		})
	}
}

// TestScanFindingsStillRedacted confirms the finding path (already redacted
// before this change) is unaffected: the default scan emits findings with no
// canary, so detection output is unchanged.
func TestScanFindingsStillRedacted(t *testing.T) {
	p := writeTranscript(t, redactCanaryTranscript)
	out, _, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"record_type":"finding"`) {
		t.Fatalf("expected findings:\n%s", out)
	}
	assertNoCanaries(t, "scan findings", out)
}
