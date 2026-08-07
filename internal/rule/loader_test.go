package rule

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadSource(t *testing.T) {
	const y = `
id: secrets.a
version: "1.0"
title: A
severity: high
expr: 'true'
enabled: true
enforce: true
deny_message: Contact the workspace owner.
`
	p, err := LoadSource(strings.NewReader(y), "secrets.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "secrets" || len(p.Rules) != 1 || p.Rules[0].ID != "secrets.a" {
		t.Fatalf("source = %+v", p)
	}
	if p.Rules[0].Version != "1.0" {
		t.Fatalf("rule version = %q, want explicit rule version", p.Rules[0].Version)
	}
	if p.Rules[0].DenyMessage != "Contact the workspace owner." {
		t.Fatalf("deny message = %q", p.Rules[0].DenyMessage)
	}
}

func TestLoadSourceSingleRuleFile(t *testing.T) {
	const y = `
id: secrets.agent_read_env
version: "1.0"
title: Agent read .env file
severity: high
expr: 'event.event_type == "command.exec" && event.command.contains(".env")'
tags:
  - secret_file_read
`
	p, err := LoadSource(strings.NewReader(y), "agent-read-env.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "agent-read-env" || len(p.Rules) != 1 {
		t.Fatalf("source = %+v", p)
	}
	r := p.Rules[0]
	if r.ID != "secrets.agent_read_env" || r.Version != "1.0" || len(r.Tags) != 1 {
		t.Fatalf("rule = %+v", r)
	}
}

func TestLoadSourceRejectsTopLevelRules(t *testing.T) {
	const y = `
name: secrets
rules:
  - id: a
    version: "1.0"
    title: A
    severity: high
    expr: 'true'
`
	_, err := LoadSource(strings.NewReader(y), "secrets.yaml")
	if err == nil || !strings.Contains(err.Error(), "one rule per file") {
		t.Fatalf("want one-rule-per-file error, got %v", err)
	}
}

func TestLoadSourceRejectsTopLevelName(t *testing.T) {
	const y = `
name: secrets
id: secrets.a
version: "1.0"
title: A
severity: high
expr: 'true'
`
	_, err := LoadSource(strings.NewReader(y), "secrets.yaml")
	if err == nil || !strings.Contains(err.Error(), "top-level name is not supported") {
		t.Fatalf("want unsupported name error, got %v", err)
	}
}

func TestLoadSourceRequiresRuleVersion(t *testing.T) {
	const y = `
id: secrets.a
title: A
severity: high
expr: 'true'
`
	_, err := LoadSource(strings.NewReader(y), "secrets.yaml")
	if err == nil || !strings.Contains(err.Error(), "missing version") {
		t.Fatalf("want missing version error, got %v", err)
	}
}

func TestLoadSourceUnknownFieldRejected(t *testing.T) {
	const y = `
id: a
version: "1.0"
severity: low
expr: 'true'
enabled: true
bogus_field: 1
`
	_, err := LoadSource(strings.NewReader(y), "x.yaml")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("want decode error for unknown field, got %v", err)
	}
}

func TestLoadSourceRejectsMultipleDocuments(t *testing.T) {
	const y = `
id: first
version: "1.0"
title: First
severity: low
expr: 'true'
---
id: second
version: "1.0"
title: Second
severity: low
expr: 'true'
`
	_, err := LoadSource(strings.NewReader(y), "multi.yaml")
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("want multiple-document error, got %v", err)
	}
}

func TestLoadSourceNameFallsBackToFilename(t *testing.T) {
	const y = `
id: supply.chain
version: "1.0"
title: Supply chain
severity: low
expr: 'true'
`
	p, err := LoadSource(strings.NewReader(y), "supply-chain.yml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "supply-chain" {
		t.Fatalf("name = %q, want supply-chain", p.Name)
	}
}

func TestLoadSourcesFSDeterministicOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/b.yaml":   {Data: []byte("id: b\nversion: \"1.0\"\ntitle: B\nseverity: low\nexpr: 'true'\n")},
		"rules/a.yaml":   {Data: []byte("id: a\nversion: \"1.0\"\ntitle: A\nseverity: low\nexpr: 'true'\n")},
		"rules/note.txt": {Data: []byte("ignored")},
	}
	sources, err := LoadSourcesFS(fsys, "rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Name != "a" || sources[1].Name != "b" {
		t.Fatalf("sources = %+v", sources)
	}
}

func TestLoadSourcesFSWalksNestedRuleFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/recon/example-rule-2.yml":        {Data: []byte("id: recon.two\nversion: \"1.0\"\ntitle: Two\nseverity: low\nexpr: 'true'\n")},
		"rules/recon/example-rule-1.yaml":       {Data: []byte("id: recon.one\nversion: \"1.0\"\ntitle: One\nseverity: low\nexpr: 'true'\n")},
		"rules/recon/example-rule-1_tests.yaml": {Data: []byte("rule_id: recon.one\ncases:\n  - name: ok\n    expect: match\n    events: []\n")},
		"rules/README.md":                       {Data: []byte("ignored")},
	}
	sources, err := LoadSourcesFS(fsys, "rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("sources = %d, want 2: %+v", len(sources), sources)
	}
	if sources[0].Name != "example-rule-1" || sources[0].Path != "rules/recon/example-rule-1.yaml" {
		t.Fatalf("first source = %+v, want nested example-rule-1", sources[0])
	}
	if sources[1].Name != "example-rule-2" || sources[1].Path != "rules/recon/example-rule-2.yml" {
		t.Fatalf("second source = %+v, want nested example-rule-2", sources[1])
	}
}

func TestLoadSourceRejectsOversize(t *testing.T) {
	big := strings.Repeat("x", maxRuleFileSize+1)
	_, err := LoadSource(strings.NewReader(big), "big.yaml")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size-cap error, got %v", err)
	}
}

func TestLoadSourceAtSizeLimitDecodes(t *testing.T) {
	// A valid rule padded with a comment up to (but not over) the cap loads.
	body := "id: ok\nversion: \"1.0\"\ntitle: OK\nseverity: low\nexpr: 'true'\n"
	pad := maxRuleFileSize - len(body)
	in := body + "#" + strings.Repeat("a", pad-1)
	p, err := LoadSource(strings.NewReader(in), "ok.yaml")
	if err != nil {
		t.Fatalf("at-limit rule should load: %v", err)
	}
	if p.Name != "ok" {
		t.Fatalf("name = %q", p.Name)
	}
}
