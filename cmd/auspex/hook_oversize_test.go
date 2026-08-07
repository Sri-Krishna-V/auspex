package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oversizePayload is a JSON object whose whitespace padding pushes it past the
// 4 MiB stdin cap (maxHookStdin). It begins with a valid-looking object so the
// only reason the decode fails is the size bound, not malformed JSON.
func oversizePayload() string {
	var b strings.Builder
	b.WriteString(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"pad":"`)
	// maxHookStdin is 4 MiB; write well past it so the bound trips mid-stream.
	b.Write(bytes.Repeat([]byte("A"), (4<<20)+1024))
	b.WriteString(`"}`)
	return b.String()
}

// A >4 MiB stdin payload in the default observe-only path must fail OPEN: the
// hook writes the inert allow passthrough ({}), exits 0, and emits a diagnostic
// naming the oversize condition. The host agent is never blocked.
func TestHookOversizeStdinObserveFailsOpen(t *testing.T) {
	var out, errb bytes.Buffer
	code := runHookEvent("pre-tool", []string{"--agent", "claude"}, strings.NewReader(oversizePayload()), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (oversize must fail open)", code)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {}", got)
	}
	if !strings.Contains(errb.String(), "oversized_payload") {
		t.Fatalf("stderr = %q, want an oversized_payload diagnostic", errb.String())
	}
}

// Oversized input suppresses enforcement and fails open.
func TestHookOversizeStdinEnforceFailsOpen(t *testing.T) {
	var out, errb bytes.Buffer
	dir := t.TempDir()
	recordsPath := filepath.Join(dir, "records.ndjson")
	code := runHookEvent("pre-tool", []string{
		"--agent", "claude", "--enforce",
		"--output", "file", "--output-file", recordsPath,
		"--state-db", filepath.Join(dir, "state.db"),
	}, strings.NewReader(oversizePayload()), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (oversize must fail open even under enforce)", code)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {} (no block)", got)
	}
	if strings.Contains(out.String(), "deny") || strings.Contains(out.String(), "block") {
		t.Fatalf("stdout = %q, oversize must never emit a block under enforce", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("agent stderr leaked payload diagnostics: %q", errb.String())
	}
	records, err := os.ReadFile(recordsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(records), "oversized_payload") {
		t.Fatalf("operator sink missing oversized_payload diagnostic: %s", records)
	}
}

// exactLenPayload builds a valid JSON object whose total byte length is exactly
// total, by sizing the "pad" string field. total must leave room for the fixed
// scaffolding (>= len(prefix)+len(suffix)).
func exactLenPayload(t *testing.T, total int) string {
	t.Helper()
	const prefix = `{"hook_event_name":"PreToolUse","pad":"`
	const suffix = `"}`
	padLen := total - len(prefix) - len(suffix)
	if padLen < 0 {
		t.Fatalf("total %d too small for scaffolding %d", total, len(prefix)+len(suffix))
	}
	body := prefix + strings.Repeat("A", padLen) + suffix
	if len(body) != total {
		t.Fatalf("built body len %d, want %d", len(body), total)
	}
	return body
}

// TestDecodeHookPayloadBoundary pins the exact cap behavior of decodeHookPayload:
// a valid body of cap-1 and of EXACTLY cap bytes must decode cleanly (no
// oversized_payload), and only cap+1 bytes may trip errOversizedPayload. The
// exactly-cap case is the off-by-one this fix corrects.
func TestDecodeHookPayloadBoundary(t *testing.T) {
	cases := []struct {
		name      string
		total     int
		wantOver  bool
		wantNoErr bool
	}{
		{"cap-1", maxHookStdin - 1, false, true},
		{"cap", maxHookStdin, false, true},
		{"cap+1", maxHookStdin + 1, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := exactLenPayload(t, c.total)
			_, err := decodeHookPayload(strings.NewReader(body))
			if c.wantNoErr {
				if err != nil {
					t.Fatalf("decode err = %v, want nil for a valid %d-byte body", err, c.total)
				}
				return
			}
			if !errors.Is(err, errOversizedPayload) {
				t.Fatalf("decode err = %v, want errOversizedPayload for a %d-byte body", err, c.total)
			}
			if !c.wantOver {
				t.Fatalf("unexpected oversize for %d-byte body", c.total)
			}
		})
	}
}

func TestDecodeHookPayloadRequiresJSONObject(t *testing.T) {
	for _, body := range []string{"null", "[]", `"text"`, "1", "true"} {
		t.Run(body, func(t *testing.T) {
			if _, err := decodeHookPayload(strings.NewReader(body)); err == nil {
				t.Fatalf("decodeHookPayload(%s) succeeded, want non-object error", body)
			}
		})
	}
	if payload, err := decodeHookPayload(strings.NewReader("{}")); err != nil || payload == nil {
		t.Fatalf("empty object = %#v, %v; want a valid non-nil map", payload, err)
	}
}

// TestHookExactCapStdinDecodes is the end-to-end form of the boundary fix: a valid
// body of EXACTLY maxHookStdin bytes must NOT be misreported as oversized — the
// hook passes through with exit 0 and no oversized_payload diagnostic.
func TestHookExactCapStdinDecodes(t *testing.T) {
	var out, errb bytes.Buffer
	body := exactLenPayload(t, maxHookStdin)
	code := runHookEvent("pre-tool", []string{"--agent", "claude"}, strings.NewReader(body), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {}", got)
	}
	if strings.Contains(errb.String(), "oversized_payload") {
		t.Fatalf("an exactly-cap payload must not trip the oversize guard: %q", errb.String())
	}
}

// A normally-sized payload still decodes and the hook still passes through: the
// bound only trips past the cap, so the common case is unaffected.
func TestHookNormalStdinUnderCapDecodes(t *testing.T) {
	var out, errb bytes.Buffer
	body := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`
	code := runHookEvent("pre-tool", []string{"--agent", "claude"}, strings.NewReader(body), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {}", got)
	}
	if strings.Contains(errb.String(), "oversized_payload") {
		t.Fatalf("a normal payload must not trip the oversize guard: %q", errb.String())
	}
}
