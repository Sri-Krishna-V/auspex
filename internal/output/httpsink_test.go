package output

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPSinkBatchesAndPosts(t *testing.T) {
	var (
		mu      sync.Mutex
		bodies  []string
		headers []http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		headers = append(headers, r.Header.Clone())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:        srv.URL,
		Auth:       HTTPAuth{Mode: AuthBearer, Token: "tok123"},
		BatchSize:  2,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run1")
	for i := 0; i < 3; i++ {
		if err := em.EmitFinding(testFinding("f")); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	// 3 findings, batch size 2 -> one full batch flushed mid-stream, one on Close.
	if len(bodies) != 2 {
		t.Fatalf("expected 2 POSTed batches, got %d", len(bodies))
	}
	total := 0
	for _, b := range bodies {
		total += strings.Count(strings.TrimSpace(b), "\n") + 1
	}
	if total != 3 {
		t.Fatalf("expected 3 NDJSON lines total, got %d", total)
	}
	if got := headers[0].Get("Authorization"); got != "Bearer tok123" {
		t.Fatalf("bearer header = %q", got)
	}
	if got := headers[0].Get("Content-Type"); got != contentTypeNDJSON {
		t.Fatalf("content-type = %q", got)
	}
	if s := sink.Stats(); s.BatchesSucceeded != 2 || s.LastStatus != 200 || s.RecordsSent != 3 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestHTTPSinkHMACSignature(t *testing.T) {
	const key = "topsecretkey"
	var (
		gotSig  string
		gotTS   string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(DefaultHMACHeader)
		gotTS = r.Header.Get(DefaultTimestampHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:        srv.URL,
		Auth:       HTTPAuth{Mode: AuthHMAC, HMACKey: []byte(key), HMACHeader: DefaultHMACHeader, TimestampHeader: DefaultTimestampHeader},
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run1")
	_ = em.EmitFinding(testFinding("h"))
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	if gotTS == "" {
		t.Fatal("missing timestamp header")
	}
	if _, err := strconv.ParseInt(gotTS, 10, 64); err != nil {
		t.Fatalf("timestamp header not unix seconds: %q", gotTS)
	}
	// Recompute the signature over "<ts>.<body>" exactly as a receiver would.
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(append([]byte(gotTS+"."), gotBody...))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature = %q, want %q", gotSig, want)
	}
}

func TestHTTPSinkAuthValidation(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: AuthBearer}}); err == nil {
		t.Fatal("want error for bearer with empty token")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: AuthHMAC}}); err == nil {
		t.Fatal("want error for hmac with empty key")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "bogus"}}); err == nil {
		t.Fatal("want error for unknown auth mode")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: AuthBearer, Token: "bad\r\ntoken"}}); err == nil {
		t.Fatal("want error for bearer token containing controls")
	}
	for _, auth := range []HTTPAuth{
		{Mode: AuthHMAC, HMACKey: []byte("key"), HMACHeader: "bad header"},
		{Mode: AuthHMAC, HMACKey: []byte("key"), HMACHeader: "X-Sig", TimestampHeader: "bad:header"},
		{Mode: AuthHMAC, HMACKey: []byte("key"), HMACHeader: "X-Sig", TimestampHeader: "x-sig"},
	} {
		if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: auth}); err == nil {
			t.Fatalf("want error for invalid auth headers: %+v", auth)
		}
	}
}

func TestHTTPSinkScrubsTransportErrorURL(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Post", URL: "https://ingest.example/path?token=secret-value", Err: errors.New("dial failed")}
	})}
	sink, err := NewHTTPSink(HTTPConfig{
		URL:        "https://ingest.example/path?token=secret-value",
		BatchSize:  1,
		Timeout:    time.Second,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sink.client.Timeout != time.Second {
		t.Fatalf("client timeout = %v, want 1s", sink.client.Timeout)
	}
	_, _ = sink.Write([]byte("{\"n\":1}\n"))
	err = sink.Close()
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("Close error = %v, want transport cause", err)
	}
	if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "ingest.example") {
		t.Fatalf("transport error leaked endpoint URL: %v", err)
	}
}

func TestResponseRequestIDIsBoundedForDiagnostics(t *testing.T) {
	value := strings.Repeat("x", maxResponseRequestID+50) + "\ncontrol"
	got := responseRequestID(http.Header{"X-Request-Id": []string{value}})
	if !strings.HasSuffix(got, "...") || len([]rune(got)) != maxResponseRequestID+3 {
		t.Fatalf("bounded request id = %q (%d runes)", got, len([]rune(got)))
	}
}

func TestHTTPSinkDoesNotFollowRedirects(t *testing.T) {
	var redirected int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:        origin.URL,
		Auth:       HTTPAuth{Mode: AuthBearer, Token: "secret"},
		BatchSize:  1,
		HTTPClient: origin.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sink.Write([]byte("{\"n\":1}\n"))
	if err := sink.Close(); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("Close error = %v, want redirect status failure", err)
	}
	if redirected != 0 {
		t.Fatalf("redirect target received %d requests, want 0", redirected)
	}
}

func TestHTTPSinkRetriesAfterEndpointRecovers(t *testing.T) {
	var (
		requests int
		bodies   []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	sink.now = func() time.Time { return now }
	sink.retryInterval = time.Second

	_, _ = sink.Write([]byte("{\"n\":1}\n"))
	if requests != 1 {
		t.Fatalf("requests after initial write = %d, want 1", requests)
	}
	_, _ = sink.Write([]byte("{\"n\":2}\n"))
	if requests != 1 {
		t.Fatalf("retry ran before deadline: %d requests", requests)
	}
	now = now.Add(2 * time.Second)
	_, _ = sink.Write([]byte("{\"n\":3}\n"))
	_, _ = sink.Write([]byte("{\"n\":4}\n"))
	_ = sink.Close()

	if requests < 4 {
		t.Fatalf("requests = %d, want retry plus resumed one-record batches", requests)
	}
	if !strings.Contains(bodies[1], "\"n\":1") || !strings.Contains(bodies[1], "\"n\":2") {
		t.Fatalf("recovery retry did not preserve buffered records: %q", bodies[1])
	}
	if stats := sink.Stats(); stats.RecordsSent != 4 {
		t.Fatalf("records sent = %d, want 4 after recovery", stats.RecordsSent)
	}
}

func TestHTTPSinkAllowInsecureOverride(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://example.com/ingest"}); err == nil {
		t.Fatal("want refusal without allow-insecure")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://example.com/ingest", AllowInsecure: true}); err != nil {
		t.Fatalf("allow-insecure should permit plain http to remote: %v", err)
	}
}

func TestHTTPSinkGzip(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("missing gzip content-encoding")
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip reader: %v", err)
			return
		}
		got, _ = io.ReadAll(zr)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, Gzip: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run1")
	_ = em.EmitFinding(testFinding("gz"))
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"gz"`)) {
		t.Fatalf("decompressed body missing finding: %q", got)
	}
}

func TestHTTPSinkServerError(t *testing.T) {
	const secretBody = "leak-me-internal-debug-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req-abc123")
		http.Error(w, secretBody, http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run1")
	// The accepted write is buffered for a possible final delivery, so the
	// emitter is NOT handed a per-record error; the failure is latched and
	// surfaced through Close instead.
	if err := em.EmitFinding(testFinding("f")); err != nil {
		t.Fatalf("buffered write should not surface a per-record error, got %v", err)
	}
	err = sink.Close()
	if err == nil || !strings.Contains(err.Error(), "server returned 500") {
		t.Fatalf("expected 500 error surfaced through Close, got %v", err)
	}
	// The response body must NOT be reflected into the error/diagnostics.
	if strings.Contains(err.Error(), secretBody) {
		t.Fatalf("response body leaked into error: %v", err)
	}
	// A safe request-id header may be surfaced for correlation.
	if !strings.Contains(err.Error(), "req-abc123") {
		t.Fatalf("expected request-id in error, got %v", err)
	}
	if s := sink.Stats(); s.BatchesFailed < 1 {
		t.Fatalf("stats = %+v", s)
	}
}

// TestHTTPSinkDeliversSummaryAfterMidStreamFailure covers the mid-stream failure
// path: the terminal record buffered afterward must still reach the receiver on
// Close so it gets a bounding summary, while the original failure is still
// reported to the caller.
func TestHTTPSinkDeliversSummaryAfterMidStreamFailure(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
		nreq   int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		nreq++
		first := nreq == 1
		bodies = append(bodies, string(b))
		mu.Unlock()
		if first {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 2, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	// Two findings fill the first batch and trigger the failing POST.
	if _, err := sink.Write([]byte(`{"record_type":"finding","n":1}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_, _ = sink.Write([]byte(`{"record_type":"finding","n":2}` + "\n")) // triggers failed flush
	if stats := sink.Stats(); !stats.PendingFailure {
		t.Fatalf("stats = %+v, want pending delivery failure", stats)
	}
	// The terminal summary is written AFTER the failure; it must still be buffered.
	_, _ = sink.Write([]byte(`{"record_type":"scan_summary","status":"partial"}` + "\n"))

	// Close makes a best-effort final POST but returns the original failure.
	if err := sink.Close(); err == nil {
		t.Fatal("Close should report the latched mid-stream failure")
	}

	mu.Lock()
	defer mu.Unlock()
	if nreq < 2 {
		t.Fatalf("expected a retry POST on Close, got %d requests", nreq)
	}
	joined := strings.Join(bodies, "")
	if !strings.Contains(joined, "scan_summary") {
		t.Fatalf("terminal scan_summary never reached the receiver; bodies=%q", bodies)
	}
	if !strings.Contains(joined, `"status":"partial"`) {
		t.Fatalf("summary should carry a non-complete status; bodies=%q", bodies)
	}
}

func TestHTTPSinkClearsPendingFailureAfterRetry(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, 0)
	sink.now = func() time.Time { return now }

	_, _ = sink.Write([]byte(`{"record_type":"event","n":1}` + "\n"))
	if stats := sink.Stats(); !stats.PendingFailure {
		t.Fatalf("stats = %+v, want pending failure", stats)
	}

	now = now.Add(time.Minute)
	_, _ = sink.Write([]byte(`{"record_type":"event","n":2}` + "\n"))
	stats := sink.Stats()
	if stats.PendingFailure || stats.BatchesFailed != 1 || stats.BatchesSucceeded != 2 {
		t.Fatalf("stats after recovery = %+v, want one failure and two successful batches", stats)
	}
	if err := sink.Close(); err == nil {
		t.Fatal("Close should retain the original delivery error after recovery")
	}
}

func TestHTTPSinkFailureBufferIsBoundedAndKeepsTail(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
		nreq   int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		nreq++
		first := nreq == 1
		bodies = append(bodies, string(b))
		mu.Unlock()
		if first {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	first := `{"record_type":"finding","n":1}` + "\n"
	second := `{"record_type":"finding","n":2}` + "\n"
	summary := `{"record_type":"scan_summary","status":"partial"}` + "\n"
	sink, err := NewHTTPSink(HTTPConfig{
		URL:            srv.URL,
		BatchSize:      1,
		MaxBufferBytes: len(second) + len(summary),
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sink.Write([]byte(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte(second)); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte(summary)); err != nil {
		t.Fatal(err)
	}
	err = sink.Close()
	if err == nil {
		t.Fatal("Close should report the latched mid-stream failure")
	}
	if !strings.Contains(err.Error(), "dropped 1 buffered records") {
		t.Fatalf("Close error should report bounded-buffer drop, got %v", err)
	}
	if stats := sink.Stats(); stats.RecordsDropped != 1 || stats.BytesDropped != len(first) {
		t.Fatalf("drop stats = %+v, want one dropped first record", stats)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) < 2 {
		t.Fatalf("expected final retry body, got %d requests", len(bodies))
	}
	final := bodies[len(bodies)-1]
	if strings.Contains(final, `"n":1`) {
		t.Fatalf("oldest failed record should have been dropped from final retry: %q", final)
	}
	if !strings.Contains(final, `"n":2`) || !strings.Contains(final, `"scan_summary"`) {
		t.Fatalf("final retry should keep newest finding and summary, got %q", final)
	}
}

// TestHTTPSinkBufferedWritesNotCountedAsEmitFailures covers the accepted-write
// semantics: after the first batch fails, records written afterward are buffered
// (and later delivered by Close), so the emitter must count them as emitted and
// must NOT log per-record emit failures. The run still surfaces the failure via
// Close.
func TestHTTPSinkBufferedWritesNotCountedAsEmitFailures(t *testing.T) {
	var nreq int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nreq++
		if nreq == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 2, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var diags bytes.Buffer
	em := New(sink, &diags, "run1")

	// Three findings: the 2nd fills the first batch and triggers the failing POST;
	// all three must still be counted and none must produce an emit-failure diag.
	for i := 0; i < 3; i++ {
		if err := em.EmitFinding(testFinding("f")); err != nil {
			em.Diag("error", "emit finding failed: "+err.Error())
		}
	}
	if got := em.Stats().FindingsEmitted; got != 3 {
		t.Fatalf("findings_emitted = %d, want 3 (buffered writes must count)", got)
	}
	if strings.Contains(diags.String(), "emit finding failed") {
		t.Fatalf("spurious per-record emit failure logged:\n%s", diags.String())
	}
	// The delivery failure must still be surfaced through Close.
	if err := sink.Close(); err == nil {
		t.Fatal("Close should report the latched mid-stream failure")
	}
}

// TestHTTPSinkRejectsEmbeddedCredentials verifies userinfo in the URL is rejected
// with a scrubbed error that does not echo the secret.
func TestHTTPSinkRejectsEmbeddedCredentials(t *testing.T) {
	_, err := NewHTTPSink(HTTPConfig{URL: "https://user:hunter2@example.com/ingest"})
	if err == nil {
		t.Fatal("want refusal of url with embedded credentials")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("error leaked credentials: %v", err)
	}
}

// TestHTTPSinkMalformedURLErrorScrubbed covers regression: a URL that fails
// url.Parse must not have its raw (secret-bearing) text echoed in the error,
// since Go's parse error commonly quotes the input.
func TestHTTPSinkMalformedURLErrorScrubbed(t *testing.T) {
	// A control byte in userinfo makes url.Parse fail outright.
	_, err := NewHTTPSink(HTTPConfig{URL: "https://user:s3cr3t@\x7f/ingest"})
	if err == nil {
		t.Fatal("want parse error for malformed url")
	}
	if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("malformed-url error leaked credentials: %v", err)
	}
}

// TestHTTPSinkHMACGoldenVector pins the signing scheme against fixed inputs so
// any change to the framing ("<ts>.<body>" vs bare body) or to the "sha256=<hex>"
// encoding is caught. The constants below were precomputed with the standard
// library for key "golden-key" and the given body.
func TestHTTPSinkHMACGoldenVector(t *testing.T) {
	const (
		key      = "golden-key"
		body     = `{"record_type":"finding","id":"x"}` + "\n"
		wantBare = "sha256=cfbc208b9c25aac6c9f991c481b4a8497077ca677e8b1d7942b0947f201c80ab"
		wantTS   = "sha256=f17f69e6bc0d8ef537887c7f6611cd13bc524e7bf59389885fed5b0ebb71526f" // over "1700000000."+body
	)

	// Bare-body branch: no timestamp header configured.
	bareReq, _ := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader(body))
	if err := applyAuth(bareReq, HTTPAuth{Mode: AuthHMAC, HMACKey: []byte(key), HMACHeader: "X-Sig"}, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if got := bareReq.Header.Get("X-Sig"); got != wantBare {
		t.Fatalf("bare-body golden vector: got %q want %q", got, wantBare)
	}

	// Timestamped framing: recompute the same way a receiver would, pinning the
	// exact "<ts>.<body>" payload and hex encoding against the precomputed value.
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("1700000000." + body))
	if got := "sha256=" + hex.EncodeToString(mac.Sum(nil)); got != wantTS {
		t.Fatalf("timestamped golden vector: got %q want %q", got, wantTS)
	}
}

// TestHTTPSinkBareBodySigning verifies that an empty timestamp header signs the
// bare body (no timestamp prefix, no timestamp header sent).
func TestHTTPSinkBareBodySigning(t *testing.T) {
	const key = "k"
	var gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Sig")
		gotTS = r.Header.Get(DefaultTimestampHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:        srv.URL,
		Auth:       HTTPAuth{Mode: AuthHMAC, HMACKey: []byte(key), HMACHeader: "X-Sig"}, // TimestampHeader empty
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run1")
	_ = em.EmitFinding(testFinding("b"))
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if gotTS != "" {
		t.Fatalf("no timestamp header expected for bare-body signing, got %q", gotTS)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("bare-body signature = %q, want %q", gotSig, want)
	}
}

func TestHTTPSinkRejectsInsecureNonLoopback(t *testing.T) {
	_, err := NewHTTPSink(HTTPConfig{URL: "http://example.com/ingest"})
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("want refusal of plain http to non-loopback, got %v", err)
	}
}

func TestHTTPSinkConfigValidation(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: ""}); err == nil {
		t.Fatalf("want error for empty url")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "ftp://x/y"}); err == nil {
		t.Fatalf("want error for bad scheme")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https:ingest"}); err == nil {
		t.Fatalf("want error for missing host")
	}
	// Loopback plain http is allowed without AllowInsecure.
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://127.0.0.1:9/x"}); err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://LOCALHOST:9/x"}); err != nil {
		t.Fatalf("uppercase localhost should be allowed: %v", err)
	}
}

func TestHTTPSinkWriteAfterClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	sink, _ := NewHTTPSink(HTTPConfig{URL: srv.URL, HTTPClient: srv.Client()})
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close should be idempotent: %v", err)
	}
	if _, err := sink.Write([]byte("x\n")); err == nil {
		t.Fatalf("write after close should error")
	}
}
