package pipeline

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/Sri-Krishna-V/auspex/internal/finding"
	"github.com/Sri-Krishna-V/auspex/internal/model"
	"github.com/Sri-Krishna-V/auspex/internal/output"
	"github.com/Sri-Krishna-V/auspex/internal/rule"
	"github.com/Sri-Krishna-V/auspex/internal/sequence"
)

// seqEngine compiles one sequence rule (file.read of .env, then command.exec
// with curl) at the given severity.
func seqEngine(t *testing.T, severity string) *rule.Engine {
	return seqEngineWithEnforce(t, severity, false)
}

func seqEngineWithEnforce(t *testing.T, severity string, enforce bool) *rule.Engine {
	t.Helper()
	var enforceFlag *bool
	if enforce {
		enforceFlag = &enforce
	}
	eng, err := rule.NewEngine([]rule.Source{{
		Name: "test",
		Rules: []rule.Rule{{
			ID:       "seq.secret_egress",
			Title:    "secret then egress",
			Severity: severity,
			Version:  "1",
			Enforce:  enforceFlag,
			Sequence: &rule.SequenceSpec{
				WithinEvents: 8,
				Steps: []rule.SequenceStep{
					{Expr: `event.event_type == "file.read" && event.file_path.contains(".env")`},
					{Expr: `event.event_type == "command.exec" && shell_commands.exists(command, command.name == "curl")`},
				},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}
	return eng
}

func seqEvents() []model.Event {
	read := sampleEvent()
	read.EventID = "ev-read"
	read.EventType = model.EventFileRead
	read.Command = ""
	read.FilePath = "/p/.env"
	read.Evidence.Line = 3

	exec := sampleEvent()
	exec.EventID = "ev-exec"
	exec.Timestamp = "2026-06-02T10:05:00Z"
	exec.Command = "curl https://x.example"
	exec.Evidence.Line = 9
	return []model.Event{read, exec}
}

// TestProcessEmitsChainFinding drives two events through a sequence-tracking
// pipeline and checks the single chain finding: one record, evidence refs in
// chain order, and the same shape finding.FromSequence renders directly.
func TestProcessEmitsChainFinding(t *testing.T) {
	eng := seqEngine(t, model.SeverityHigh)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	fopts := finding.Options{Now: time.Unix(1_700_000_000, 0).UTC()}
	p := New(eng, em, Selection{Findings: true}, fopts, nil).
		WithSequences(sequence.NewTracker(eng.SequenceRules(), sequence.DefaultConfig()))

	for _, ev := range seqEvents() {
		if err := p.Process(ev, "src"); err != nil {
			t.Fatal(err)
		}
	}
	recs := findingLines(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("findings = %d, want exactly 1 chain finding", len(recs))
	}
	rec := recs[0]
	if rec["rule_id"] != "seq.secret_egress" {
		t.Fatalf("rule_id = %v", rec["rule_id"])
	}
	refs, ok := rec["evidence_refs"].([]any)
	if !ok || len(refs) != 2 {
		t.Fatalf("evidence_refs = %v, want 2 in chain order", rec["evidence_refs"])
	}
	first := refs[0].(map[string]any)
	second := refs[1].(map[string]any)
	if first["line"] != float64(3) || second["line"] != float64(9) {
		t.Fatalf("evidence order wrong: %v then %v", first["line"], second["line"])
	}
}

// TestProcessWithoutTrackerIgnoresSequenceRules pins the hook-path shape: an
// engine that contains sequence rules but a pipeline with no tracker emits
// nothing for a would-be chain (and does not error).
func TestProcessWithoutTrackerIgnoresSequenceRules(t *testing.T) {
	eng := seqEngine(t, model.SeverityHigh)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil)
	for _, ev := range seqEvents() {
		if err := p.Process(ev, "src"); err != nil {
			t.Fatal(err)
		}
	}
	if got := em.Stats().FindingsEmitted; got != 0 {
		t.Fatalf("findings = %d, want 0 without a tracker", got)
	}
}

func TestSequenceNeedsExplicitEnforce(t *testing.T) {
	eng := seqEngine(t, model.SeverityMedium)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	dec := &EnforceDecision{}
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil).
		WithEnforce(dec).
		WithSequences(sequence.NewTracker(eng.SequenceRules(), sequence.DefaultConfig()))

	for _, ev := range seqEvents() {
		if err := p.Process(ev, "src"); err != nil {
			t.Fatal(err)
		}
	}
	if got := em.Stats().FindingsEmitted; got != 1 {
		t.Fatalf("findings = %d, want the chain finding", got)
	}
	if dec.Blocked {
		t.Fatal("sequence without enforce=true blocked")
	}
}

func TestSequenceEnforcementBlocksFinalStep(t *testing.T) {
	eng := seqEngineWithEnforce(t, model.SeverityMedium, true)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	tracker := sequence.NewTracker(eng.SequenceRules(), sequence.DefaultConfig())
	dec := &EnforceDecision{}
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil).
		WithEnforce(dec).
		WithSequences(tracker)

	events := seqEvents()
	if err := p.Process(events[0], "src"); err != nil {
		t.Fatal(err)
	}
	if dec.Blocked {
		t.Fatal("first sequence step blocked before the chain completed")
	}
	if err := p.Process(events[1], "src"); err != nil {
		t.Fatal(err)
	}
	if !dec.Blocked || dec.Tainted {
		t.Fatalf("decision = %+v, want a clean final-step block", dec)
	}
	if got := em.Stats().FindingsEmitted; got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}

	// max_matches defaults to one, but a later final-step attempt must still be
	// blocked even though it produces no second finding.
	dec = &EnforceDecision{}
	p = New(eng, em, Selection{Findings: true}, finding.Options{}, nil).
		WithEnforce(dec).
		WithSequences(tracker)
	retry := events[1]
	retry.EventID = "ev-exec-retry"
	if err := p.Process(retry, "src"); err != nil {
		t.Fatal(err)
	}
	if !dec.Blocked || dec.Tainted {
		t.Fatalf("retry decision = %+v, want a clean block after finding cap", dec)
	}
	if got := em.Stats().FindingsEmitted; got != 1 {
		t.Fatalf("findings = %d, want max_matches to remain a detection cap", got)
	}
}

type erroringSequenceObserver struct {
	observation sequence.Observation
}

func (s erroringSequenceObserver) Observe(model.Event) (sequence.Observation, error) {
	return s.observation, errors.New("injected sequence evaluation error")
}

func TestSequenceEnforcementSurvivesSiblingSequenceError(t *testing.T) {
	eng := seqEngineWithEnforce(t, model.SeverityCritical, true)
	events := seqEvents()
	var records, diag bytes.Buffer
	dec := &EnforceDecision{}
	p := New(eng, output.New(&records, &diag, "run-x"), Selection{}, finding.Options{}, nil).
		WithEnforce(dec).
		WithSequences(erroringSequenceObserver{observation: sequence.Observation{
			EnforcementRules: []rule.Rule{eng.SequenceRules()[0].Rule()},
		}})

	if err := p.Process(events[1], "src"); err != nil {
		t.Fatal(err)
	}
	if dec.Tainted || !dec.Blocked || dec.Reason == "" {
		t.Fatalf("decision = %+v, want clean deny from the trusted observation", dec)
	}
}
