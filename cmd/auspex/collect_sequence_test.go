package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/output"
)

// eventCountChainRule is a sequence rule windowed by event count only: live
// OTLP records do not always carry timestamps, and a wall-clock window
// fails closed without them — the event-count window is the right tool for a
// live receiver, and this test exercises exactly that mode.
const eventCountChainRule = `id: chain.env_read_then_curl_live
version: "1.0"
title: Env read then curl over live telemetry
severity: high
sequence:
  within_events: 32
  steps:
    - expr: 'event.event_type == "file.read" && event.file_path.contains(".env")'
    - expr: 'event.event_type == "command.exec" && event.command.contains("curl")'
`

// TestCollectHandlerEmitsChainFinding posts two OTLP exports — a .env read,
// then a curl exec, same session — and asserts the receiver assembles the
// chain across batches into one finding.
func TestCollectHandlerEmitsChainFinding(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "chains.yaml"), []byte(eventCountChainRule), 0o644); err != nil {
		t.Fatal(err)
	}
	var records, diags bytes.Buffer
	em := output.New(&records, &diags, "run-test")
	c, err := newCollector(collectorConfig{
		emit:      em,
		sel:       emitSelection{findings: true},
		ruleDirs:  multiFlag{dir},
		noBuiltin: true,
	})
	if err != nil {
		t.Fatalf("newCollector: %v", err)
	}

	// Two separate posts: the window must persist across handler invocations.
	first := buildOTLPLogs("claude-code", []map[string]string{
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/p/.env", "session.id": "s1"},
	})
	second := buildOTLPLogs("claude-code", []map[string]string{
		{"process.command": "curl https://collector.example", "session.id": "s1"},
	})
	for _, body := range [][]byte{first, second} {
		if rr := postLogs(t, c, body, "application/x-protobuf"); rr.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
		}
	}

	var chains int
	for _, line := range strings.Split(strings.TrimSpace(records.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad record JSON %q: %v", line, err)
		}
		if rec["record_type"] == output.RecordFinding && rec["rule_id"] == "chain.env_read_then_curl_live" {
			chains++
			refs, ok := rec["evidence_refs"].([]any)
			if !ok || len(refs) != 2 {
				t.Errorf("chain finding evidence_refs = %v, want 2", rec["evidence_refs"])
			}
		}
	}
	if chains != 1 {
		t.Fatalf("chain findings = %d, want 1\nrecords: %s", chains, records.String())
	}
}

// TestCollectHandlerNoChainAcrossSessions: the same two steps in different
// live sessions must not correlate.
func TestCollectHandlerNoChainAcrossSessions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "chains.yaml"), []byte(eventCountChainRule), 0o644); err != nil {
		t.Fatal(err)
	}
	var records, diags bytes.Buffer
	em := output.New(&records, &diags, "run-test")
	c, err := newCollector(collectorConfig{
		emit:      em,
		sel:       emitSelection{findings: true},
		ruleDirs:  multiFlag{dir},
		noBuiltin: true,
	})
	if err != nil {
		t.Fatalf("newCollector: %v", err)
	}
	body := buildOTLPLogs("claude-code", []map[string]string{
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/p/.env", "session.id": "s1"},
		{"process.command": "curl https://collector.example", "session.id": "s2"},
	})
	if rr := postLogs(t, c, body, "application/x-protobuf"); rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	if out := records.String(); strings.Contains(out, "chain.env_read_then_curl_live") {
		t.Fatalf("cross-session chain must not assemble:\n%s", out)
	}
}
