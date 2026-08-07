package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type errSink struct {
	bytes.Buffer
	err error
}

func (e *errSink) Write(p []byte) (int, error) {
	e.Buffer.Write(p)
	return len(p), e.err
}

func (e *errSink) Close() error { return nil }

type statsSink struct {
	bytes.Buffer
	stats SinkStats
}

func (s *statsSink) Close() error     { return nil }
func (s *statsSink) Stats() SinkStats { return s.stats }

func TestMultiSinkWritesEveryChild(t *testing.T) {
	var a, b bytes.Buffer
	sink := NewMultiSink(nopCloseSink{&a}, nopCloseSink{&b})
	line := []byte(`{"record_type":"event"}` + "\n")
	if n, err := sink.Write(line); err != nil || n != len(line) {
		t.Fatalf("write = (%d, %v), want full nil", n, err)
	}
	if a.String() != string(line) || b.String() != string(line) {
		t.Fatalf("fanout mismatch: a=%q b=%q", a.String(), b.String())
	}
}

func TestMultiSinkAttemptsAllChildrenOnError(t *testing.T) {
	bad := &errSink{err: errors.New("boom")}
	var good bytes.Buffer
	sink := NewMultiSink(bad, nopCloseSink{&good})
	line := []byte(`{"record_type":"finding"}` + "\n")
	if _, err := sink.Write(line); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("write error = %v, want boom", err)
	}
	if bad.String() != string(line) || good.String() != string(line) {
		t.Fatalf("write should reach all sinks: bad=%q good=%q", bad.String(), good.String())
	}
}

func TestMultiSinkPropagatesPendingFailure(t *testing.T) {
	degraded := &statsSink{stats: SinkStats{HTTPTransport: true, PendingFailure: true}}
	healthy := &statsSink{stats: SinkStats{HTTPTransport: true}}
	sink := NewMultiSink(degraded, healthy)
	if stats := sink.(StatsReporter).Stats(); !stats.PendingFailure {
		t.Fatalf("stats = %+v, want pending failure", stats)
	}
}
