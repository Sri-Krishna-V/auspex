package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// httpSummary extends the asserted scan_summary subset with the HTTP delivery
// fields, so http-mode tests can check stats and the failure indicator.
type httpSummary struct {
	RecordType      string `json:"record_type"`
	Status          string `json:"status"`
	HTTPBatchesSent *int   `json:"http_batches_sent"`
	HTTPRecordsSent *int   `json:"http_records_sent"`
	HTTPLastStatus  *int   `json:"http_last_status"`
	HTTPFailed      *bool  `json:"http_failed"`
}

func decodeHTTPSummary(t *testing.T, ndjson string) httpSummary {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(ndjson), "\n") {
		if line == "" {
			continue
		}
		var s httpSummary
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("line not JSON: %v\n%s", err, line)
		}
		if s.RecordType == "scan_summary" {
			return s
		}
	}
	t.Fatalf("no scan_summary in:\n%s", ndjson)
	return httpSummary{}
}

func TestScanOutputFlagValidation(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad-mode", []string{"--output", "bogus"}, "invalid --output"},
		{"duplicate-mode", []string{"--output", "file", "--output", "file"}, "duplicate"},
		{"comma-mode", []string{"--output", "file,http"}, "pass one sink per flag"},
		{"stdout-combined", []string{"--output", "stdout", "--output", "http"}, "stdout cannot be combined"},
		{"file-without-path", []string{"--output", "file"}, "requires --output-file"},
		{"http-without-url", []string{"--output", "http"}, "requires --http-url"},
		{"fanout-without-file", []string{"--output", "file", "--output", "http", "--http-url", "https://x"}, "requires --output-file"},
		{"fanout-without-url", []string{"--output", "file", "--output", "http", "--output-file", "/tmp/x"}, "requires --http-url"},
		{"file-flag-wrong-mode", []string{"--output", "stdout", "--output-file", "/tmp/x"}, "--output-file is only valid"},
		{"url-flag-wrong-mode", []string{"--output", "stdout", "--http-url", "https://x"}, "--http-url is only valid"},
		// HTTP-only tuning flags must be rejected outside HTTP mode with the same
		// cross-mode style as --http-url.
		{"http-auth-wrong-mode", []string{"--output", "stdout", "--http-auth", "bearer"}, "--http-auth is only valid when --output includes http"},
		{"http-batch-wrong-mode", []string{"--output", "stdout", "--http-batch-size", "100"}, "--http-batch-size is only valid when --output includes http"},
		{"http-timeout-wrong-mode", []string{"--output", "file", "--output-file", "/tmp/x", "--http-timeout", "5s"}, "--http-timeout is only valid when --output includes http"},
		{"http-gzip-wrong-mode", []string{"--output", "stdout", "--http-gzip"}, "--http-gzip is only valid when --output includes http"},
		{"http-sig-header-wrong-mode", []string{"--output", "stdout", "--http-sig-header", "X-Sig"}, "--http-sig-header is only valid when --output includes http"},
		{"http-sig-header-without-hmac", []string{"--output", "http", "--http-url", "https://x", "--http-sig-header", "X-Sig"}, "--http-sig-header requires --http-auth hmac-sha256"},
		{"http-timestamp-header-with-bearer", []string{"--output", "http", "--http-url", "https://x", "--http-auth", "bearer", "--http-timestamp-header", "X-Time"}, "--http-timestamp-header requires --http-auth hmac-sha256"},
		{"http-allow-insecure-wrong-mode", []string{"--output", "stdout", "--http-allow-insecure"}, "--http-allow-insecure is only valid when --output includes http"},
		{"blank-file-path", []string{"--output", "file", "--output-file", "   "}, "requires --output-file"},
		{"bad-auth", []string{"--output", "http", "--http-url", "https://x", "--http-auth", "bogus"}, "invalid --http-auth"},
		{"zero-batch", []string{"--output", "http", "--http-url", "https://x", "--http-batch-size", "0"}, "--http-batch-size must be a positive"},
		{"negative-batch", []string{"--output", "http", "--http-url", "https://x", "--http-batch-size", "-5"}, "--http-batch-size must be a positive"},
		{"zero-timeout", []string{"--output", "http", "--http-url", "https://x", "--http-timeout", "0"}, "--http-timeout must be a positive"},
		{"url-with-creds", []string{"--output", "http", "--http-url", "https://u:p@x/ingest"}, "must not contain embedded credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errb, code := runCLI(append([]string{"scan", "--path", p}, tc.args...)...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.Contains(errb, tc.want) {
				t.Fatalf("stderr = %q, want substring %q", errb, tc.want)
			}
		})
	}
}

func TestScanInvalidHTTPConfigDoesNotTruncateFileOutput(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out := filepath.Join(t.TempDir(), "records.ndjson")
	const original = "existing records\n"
	if err := os.WriteFile(out, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	_, errb, code := runCLI("scan", "--path", p,
		"--output", "file", "--output", "http",
		"--output-file", out, "--http-url", "https://")
	if code != 2 || !strings.Contains(errb, "url must include a host") {
		t.Fatalf("exit = %d, stderr = %q", code, errb)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("file changed during failed sink setup: %q", got)
	}
}

func TestScanFileOutput(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out := filepath.Join(t.TempDir(), "records.ndjson")
	stdout, _, code := runCLI("scan", "--path", p, "--output", "file", "--output-file", out)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("stdout should be empty in file mode, got %q", stdout)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("file perms = %o, want 600", perm)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := decodeHTTPSummary(t, string(b))
	if s.Status != "complete" {
		t.Fatalf("file-mode summary status = %q, want complete", s.Status)
	}
	// A non-http run must omit the entire http_* block (keys absent), keeping
	// file/stdout summaries byte-identical to before sinks existed.
	if s.HTTPBatchesSent != nil || s.HTTPRecordsSent != nil || s.HTTPLastStatus != nil || s.HTTPFailed != nil {
		t.Fatalf("file-mode summary must omit all http_* keys, got %+v", s)
	}
	if strings.Contains(string(b), "http_") {
		t.Fatalf("file-mode summary leaked an http_ key:\n%s", b)
	}
}

func TestScanHTTPOutputSuccess(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := writeTranscript(t, scanTranscript)
	stdout, _, code := runCLI("scan", "--path", p, "--emit", "all",
		"--output", "http", "--http-url", srv.URL, "--http-allow-insecure", "--http-batch-size", "2")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("stdout should be empty in http mode, got %q", stdout)
	}

	// The terminal scan_summary must be in the last delivered batch.
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no batches received")
	}
	all := bytes.Join(bodies, nil)
	s := decodeHTTPSummary(t, string(all))
	if s.Status != "complete" {
		t.Fatalf("summary status = %q, want complete", s.Status)
	}
	if !bytes.Contains(bodies[len(bodies)-1], []byte(`"scan_summary"`)) {
		t.Fatal("scan_summary not in the final batch")
	}
	if s.HTTPFailed == nil || *s.HTTPFailed {
		t.Fatalf("http_failed should be present and false on a successful run, got %v", s.HTTPFailed)
	}
	// An http run must emit honest (possibly zero) transport counters, not omit
	// them: http_records_sent is present even when the records all landed in the
	// final summary-carrying batch.
	if s.HTTPRecordsSent == nil {
		t.Fatal("http_records_sent omitted on an http run; want an explicit value")
	}
	if s.HTTPBatchesSent == nil || s.HTTPLastStatus == nil {
		t.Fatalf("http_batches_sent/http_last_status omitted on an http run")
	}
}

func TestScanFileAndHTTPOutputSuccess(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := writeTranscript(t, scanTranscript)
	out := filepath.Join(t.TempDir(), "records.ndjson")
	stdout, _, code := runCLI("scan", "--path", p, "--emit", "all",
		"--output", "file",
		"--output", "http",
		"--output-file", out,
		"--http-url", srv.URL,
		"--http-allow-insecure",
		"--http-batch-size", "2")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("stdout should be empty in file+http mode, got %q", stdout)
	}
	fileBody, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if s := decodeHTTPSummary(t, string(fileBody)); s.Status != "complete" {
		t.Fatalf("file copy summary status = %q, want complete", s.Status)
	}
	mu.Lock()
	httpBody := bytes.Join(bodies, nil)
	mu.Unlock()
	if len(httpBody) == 0 {
		t.Fatal("no HTTP batches received")
	}
	if s := decodeHTTPSummary(t, string(httpBody)); s.Status != "complete" {
		t.Fatalf("http copy summary status = %q, want complete", s.Status)
	}
}

func TestScanHTTPOutputFailureSurfaced(t *testing.T) {
	// Every POST returns 500: delivery fails. The run must not report complete,
	// must exit non-zero, and must surface the failure on stderr.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := writeTranscript(t, scanTranscript)
	_, errb, code := runCLI("scan", "--path", p,
		"--output", "http", "--http-url", srv.URL, "--http-allow-insecure", "--http-batch-size", "1")
	if code == 0 {
		t.Fatal("expected non-zero exit on delivery failure")
	}
	if !strings.Contains(errb, "delivery failed") && !strings.Contains(errb, "server returned 500") {
		t.Fatalf("stderr missing delivery failure: %q", errb)
	}
}

func TestScanHTTPBearerFromEnv(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv(envHTTPToken, "secret-token")
	p := writeTranscript(t, scanTranscript)
	_, _, code := runCLI("scan", "--path", p,
		"--output", "http", "--http-url", srv.URL, "--http-allow-insecure", "--http-auth", "bearer")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

func TestScanHTTPBearerMissingEnv(t *testing.T) {
	t.Setenv(envHTTPToken, "") // ensure unset regardless of host environment
	p := writeTranscript(t, scanTranscript)
	_, errb, code := runCLI("scan", "--path", p,
		"--output", "http", "--http-url", "https://x.example", "--http-auth", "bearer")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, envHTTPToken) {
		t.Fatalf("stderr should name the env var: %q", errb)
	}
}
