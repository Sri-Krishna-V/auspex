package extract

import (
	"io"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// artifactCoworkJSONL is the Evidence.ArtifactType for Claude Cowork
// (local-agent-mode / Dispatch) session transcripts. Cowork writes an
// audit.jsonl per session whose records follow the same Claude-Code JSONL schema
// the ClaudeExtractor already parses; only the source identity differs.
const artifactCoworkJSONL = "cowork_jsonl"

// CoworkExtractor parses audit.jsonl with the shared Claude transcript parser,
// changing only source identity and artifact type. Cowork has no documented
// synchronous hook contract, so auspex supports it only through artifacts.
//
// The zero value is ready to use.
type CoworkExtractor struct {
	maxBytes int
}

// core builds the underlying Claude parser configured to stamp Cowork identity.
func (e CoworkExtractor) core() ClaudeExtractor {
	return ClaudeExtractor{
		maxBytes:     e.maxBytes,
		sourceAgent:  model.AgentCowork,
		artifactType: artifactCoworkJSONL,
	}
}

// Agent identifies the events this extractor produces.
func (CoworkExtractor) Agent() string { return model.AgentCowork }

// Extract parses a Cowork audit.jsonl transcript by delegating to the shared
// Claude-Code parser, which stamps the Cowork source agent and artifact type.
func (e CoworkExtractor) Extract(r io.Reader, src Source) (*Result, error) {
	return e.core().Extract(r, src)
}
