package extract

import (
	"io"
	"strings"
	"testing"
)

// panicParser always panics, standing in for a corrupt or adversarial artifact
// whose parser faults mid-stream.
type panicParser struct{}

func (panicParser) Agent() string { return "panic" }
func (panicParser) Extract(io.Reader, Source) (*Result, error) {
	panic("boom: secret artifact value")
}

type nilParser struct{}

func (nilParser) Agent() string                              { return "nil" }
func (nilParser) Extract(io.Reader, Source) (*Result, error) { return nil, nil }

// okParser returns a fixed result without panicking, to prove SafeExtract is a
// transparent passthrough on the happy path.
type okParser struct{}

func (okParser) Agent() string { return "ok" }
func (okParser) Extract(io.Reader, Source) (*Result, error) {
	return &Result{Events: nil, Diagnostics: []Diagnostic{{Path: "p", Line: 1, Msg: "noted"}}}, nil
}

// TestSafeExtractRecoversPanic confirms a panicking parser becomes an error (not
// an unwind) and yields no partial result, so the caller can skip the artifact.
func TestSafeExtractRecoversPanic(t *testing.T) {
	res, err := SafeExtract(panicParser{}, strings.NewReader("x"), Source{Path: "bad"})
	if err == nil {
		t.Fatal("SafeExtract returned nil error for a panicking parser")
	}
	if res != nil {
		t.Fatalf("SafeExtract returned a non-nil result on panic: %+v", res)
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Fatalf("error = %v, want it to name the recovered panic", err)
	}
	if strings.Contains(err.Error(), "secret artifact value") {
		t.Fatalf("panic diagnostic leaked panic value: %v", err)
	}
}

func TestSafeExtractRejectsNilResult(t *testing.T) {
	res, err := SafeExtract(nilParser{}, strings.NewReader("x"), Source{Path: "bad"})
	if err == nil || res != nil {
		t.Fatalf("SafeExtract = (%+v, %v), want nil result error", res, err)
	}
}

// TestSafeExtractPassesThroughOnSuccess confirms SafeExtract returns the
// parser's result and nil error unchanged when no panic occurs.
func TestSafeExtractPassesThroughOnSuccess(t *testing.T) {
	res, err := SafeExtract(okParser{}, strings.NewReader("x"), Source{Path: "good"})
	if err != nil {
		t.Fatalf("SafeExtract errored on a clean parse: %v", err)
	}
	if res == nil || len(res.Diagnostics) != 1 || res.Diagnostics[0].Msg != "noted" {
		t.Fatalf("SafeExtract did not pass the result through: %+v", res)
	}
}
