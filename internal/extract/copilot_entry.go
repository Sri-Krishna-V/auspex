package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// copilotEntry is a tolerant view of one GitHub Copilot CLI at-rest event record
// (~/.copilot/session-state/<session-id>/events.jsonl, one JSON object per line).
//
// Copilot's events.jsonl schema is NOT documented or stable: the records are
// written live by the CLI runtime and vary across builds, so every field is
// decoded defensively across the spelling variants seen in practice — mirroring
// how auspex's Copilot live-hook resolver reads a loosely-typed Copilot payload
// (see internal/hook) rather than binding one rigid schema. Only the fields
// auspex maps are pulled out; anything else is ignored so an unrelated schema
// addition never breaks the parse. No field is synthesized: a value absent from
// the record stays empty.
//
// The tool-name and argument-key vocabulary intentionally tracks the verified
// Copilot live-hook vocabulary (ShellCommand/ReadFile/WriteFile/WebFetch, with
// snake_case and Claude-style aliases; command/cmd, path/filePath, url, query),
// because both surfaces are produced by the same Copilot runtime.
type copilotEntry struct {
	// Type/EventType/Role discriminate the record. Copilot has tagged records by a
	// hook-style event name (PreToolUse/PostToolUse/UserPromptSubmitted), by a
	// generic "type", and by a message "role"; all are accepted. The hook-style
	// event name wins when present because it most precisely names the moment.
	Type      string `json:"type"`
	EventType string `json:"eventType"`
	EventName string `json:"hookEventName"`
	Event     string `json:"event"`
	Role      string `json:"role"`

	// Identity / context. Copilot keys the events file directory by session id and
	// also stamps the record with a session/conversation id; each is read across
	// the spellings observed, first non-empty winning. The working directory is
	// likewise read across spellings.
	ID             string `json:"id"`
	EventID        string `json:"eventId"`
	MessageID      string `json:"messageId"`
	SessionIDField string `json:"sessionId"`
	SessionSnake   string `json:"session_id"`
	ConversationID string `json:"conversationId"`
	Timestamp      any    `json:"timestamp"`
	CreatedAt      any    `json:"createdAt"`
	Time           any    `json:"time"`
	CWD            string `json:"cwd"`
	WorkingDir     string `json:"workingDirectory"`
	WorkingSnake   string `json:"working_directory"`
	WorkspacePath  string `json:"workspacePath"`

	// Content / Text / Prompt hold the free-text body of a user prompt or assistant
	// message. Copilot encodes it as a plain string under any of these keys; the
	// first non-empty wins, and its source pointer is resolved by text().
	Content copilotText `json:"content"`
	Text    string      `json:"text"`
	Message string      `json:"message"`
	Prompt  string      `json:"prompt"`

	// ToolName names the invoked tool (ShellCommand/ReadFile/WebFetch/...). It is
	// read across spellings by toolName().
	ToolName  string `json:"toolName"`
	ToolSnake string `json:"tool_name"`
	Tool      string `json:"tool"`

	// ToolArgs carries the tool's arguments. Copilot encodes toolArgs either as a
	// JSON object or as a JSON-ENCODED STRING (mirroring its live-hook payload), so
	// copilotArgs decodes both. Per Copilot's contract these are the ONLY argument
	// keys — the parser deliberately does NOT consult generic tool_input/input/args
	// keys, exactly as the live resolver.copilotToolArgs does, so a contradictory
	// payload that also carries a stray input/args object cannot leak a value from
	// the wrong key (a missing toolArgs stays empty, never fabricated).
	ToolArgs  copilotArgs `json:"toolArgs"`
	ToolArgs2 copilotArgs `json:"tool_args"`

	// ToolCallID correlates a tool call with its later result, read across
	// spellings. Copilot has stamped this as toolCallId/callId/id.
	ToolCallID string `json:"toolCallId"`
	CallID     string `json:"callId"`
	ToolUseID  string `json:"toolUseId"`

	// ExitCode / Error / Status carry a tool result's STRUCTURED outcome. The exit
	// code and error flag are read ONLY when the record carries them structurally;
	// auspex never scrapes a prose body for a failure signal or an exit status.
	ExitCode  *int   `json:"exitCode"`
	ExitSnake *int   `json:"exit_code"`
	Error     string `json:"error"`
	IsError   *bool  `json:"isError"`
	IsErrAlt  *bool  `json:"is_error"`
	Status    string `json:"status"`
}

// copilotText is the normalized string body of a Copilot record's "content"
// field. Copilot writes content as a plain string; an object or array body
// carries nothing auspex maps and yields an empty text rather than an error,
// keeping the parse tolerant of partial records. Pointer is the RFC 6901 pointer
// to the body in the SOURCE record ("/content"), set only when a string body is
// present.
type copilotText struct {
	Text    string
	Pointer string
}

// UnmarshalJSON accepts only a plain-string content body (the shape Copilot
// uses); any other JSON shape leaves the body empty. A missing or null content
// is not an error.
func (c *copilotText) UnmarshalJSON(b []byte) error {
	raw := strings.TrimSpace(string(b))
	if raw == "" || raw == "null" {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		c.Text = s
		c.Pointer = "/content"
	}
	return nil
}

// copilotArgs is the decoded tool-argument object. Copilot encodes the arguments
// EITHER as a JSON object OR as a JSON-ENCODED STRING (the same worst-case shape
// the live hook handles), so UnmarshalJSON normalizes both into a map. present
// records whether the key was present at all, so a fallback key is consulted only
// when toolArgs is genuinely absent. A malformed encoded string decodes to no
// object — never a panic and never a fabricated value.
type copilotArgs struct {
	fields  map[string]json.RawMessage
	present bool
}

// UnmarshalJSON normalizes the object and JSON-encoded-string encodings of a
// Copilot tool-argument blob. A string body is unquoted and re-parsed as an
// object; a value that does not parse leaves an empty (but present) field set.
func (a *copilotArgs) UnmarshalJSON(b []byte) error {
	a.present = true
	raw := strings.TrimSpace(string(b))
	if raw == "" || raw == "null" {
		return nil
	}
	switch raw[0] {
	case '{':
		// A direct object: decode in place. A malformed object leaves fields nil.
		_ = json.Unmarshal(b, &a.fields)
	case '"':
		// A JSON-encoded string: unquote, then parse the inner JSON as an object.
		var s string
		if json.Unmarshal(b, &s) != nil {
			return nil
		}
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "{") {
			_ = json.Unmarshal([]byte(s), &a.fields)
		}
	}
	return nil
}

// kind reports the record's discriminator, preferring the hook-style event name
// (PreToolUse/PostToolUse/UserPromptSubmitted), then a generic type, then a
// message role. The result is lowercased so spelling case collapses.
func (e *copilotEntry) kind() string {
	if k := firstNonEmpty(e.EventName, e.Event, e.EventType, e.Type, e.Role); k != "" {
		return strings.ToLower(k)
	}
	return ""
}

// isPostMoment reports whether the record's kind names a result/post-tool moment,
// so a shell tool result is mapped to command.result with its structured exit
// code rather than to command.exec.
func (e *copilotEntry) isPostMoment() bool {
	switch e.kind() {
	case "posttooluse", "post-tool", "post_tool", "posttool", "tool_result", "toolresult", "tool.result":
		return true
	default:
		return false
	}
}

// isPreMoment reports whether the record's kind names a pre-tool/invocation
// moment.
func (e *copilotEntry) isPreMoment() bool {
	switch e.kind() {
	case "pretooluse", "pre-tool", "pre_tool", "pretool", "tool_call", "toolcall", "tool.call", "tool_use", "tooluse":
		return true
	default:
		return false
	}
}

// hasTool reports whether the record carries a tool invocation (a tool name or a
// pre/post-tool moment). A record with neither carries only a message body.
func (e *copilotEntry) hasTool() bool {
	return e.toolName() != "" || e.isPreMoment() || e.isPostMoment()
}

// sessionID resolves the session/conversation identity across spellings.
func (e *copilotEntry) sessionID() string {
	return firstNonEmpty(e.SessionIDField, e.SessionSnake, e.ConversationID)
}

// project resolves the working directory / workspace path across spellings.
func (e *copilotEntry) project() string {
	return firstNonEmpty(e.CWD, e.WorkingDir, e.WorkingSnake, e.WorkspacePath)
}

// time resolves the record timestamp. Only a string is returned (as-is), since
// auspex's Timestamp field is RFC3339 and a bare numeric epoch is not one — a
// numeric epoch therefore yields "" rather than a fabricated/format-guessed
// timestamp. The record still lands in artifact order, it just carries no time.
func (e *copilotEntry) time() string {
	for _, v := range []any{e.Timestamp, e.CreatedAt, e.Time} {
		if s := timeString(v); s != "" {
			return s
		}
	}
	return ""
}

// text returns the record's body together with the RFC 6901 pointer to it in the
// SOURCE record, preferring the structured content over the flat fallbacks. The
// content body points at "/content"; the flat fallbacks point at their own key.
func (e *copilotEntry) text() (string, string) {
	if s := strings.TrimSpace(e.Content.Text); s != "" {
		return s, e.Content.Pointer
	}
	if s := strings.TrimSpace(e.Text); s != "" {
		return s, "/text"
	}
	if s := strings.TrimSpace(e.Message); s != "" {
		return s, "/message"
	}
	if s := strings.TrimSpace(e.Prompt); s != "" {
		return s, "/prompt"
	}
	return "", ""
}

// toolName resolves the invoked tool's name across spellings.
func (e *copilotEntry) toolName() string {
	return firstNonEmpty(e.ToolName, e.ToolSnake, e.Tool)
}

// toolCallID resolves the tool call/result correlation id across spellings.
func (e *copilotEntry) toolCallID() string {
	return firstNonEmpty(e.ToolCallID, e.CallID, e.ToolUseID)
}

// toolArgsPointer returns the RFC 6901 pointer to the tool-argument blob in the
// SOURCE record, naming the exact key the arguments were read from. It mirrors
// the resolution order of args() so the emitted evidence reference is
// source-faithful.
func (e *copilotEntry) toolArgsPointer() string {
	if e.ToolArgs.present {
		return "/toolArgs"
	}
	if e.ToolArgs2.present {
		return "/tool_args"
	}
	return ""
}

// args resolves the tool's argument object. Per Copilot's contract the arguments
// live ONLY under toolArgs/tool_args (the JSON-encoded-string-or-object shape
// copilotArgs decodes); the parser deliberately does NOT fall back to generic
// toolInput/input/args keys, mirroring resolver.copilotToolArgs. A record that
// carries no toolArgs therefore yields no argument object — so a stray generic
// input/args object can never promote a tool into command.exec/file.*/network,
// holding the locked "absent -> empty, false negative over false positive" rule.
// A missing or malformed toolArgs decodes to nil rather than a fabricated value.
func (e *copilotEntry) args() map[string]json.RawMessage {
	if e.ToolArgs.present {
		return e.ToolArgs.fields
	}
	if e.ToolArgs2.present {
		return e.ToolArgs2.fields
	}
	return nil
}

// exitCode returns the STRUCTURED process exit code, or nil when the record
// carries none (so a clean exit 0 stays distinct from absent). It is read only
// from a structured field, never scraped from output text.
func (e *copilotEntry) exitCode() *int {
	if e.ExitCode != nil {
		return e.ExitCode
	}
	return e.ExitSnake
}

// errored reports whether the result is structurally marked as a failure: a
// non-empty error field, an is_error flag, or a status of "error"/"failed". A
// non-zero exit code alone is NOT treated as an error (a command may exit
// non-zero by design); the exit code rides on the command.result for a rule to
// judge. This mirrors the explicit-only failure policy the other parsers use.
func (e *copilotEntry) errored() bool {
	if strings.TrimSpace(e.Error) != "" {
		return true
	}
	if e.IsError != nil {
		return *e.IsError
	}
	if e.IsErrAlt != nil {
		return *e.IsErrAlt
	}
	s := strings.ToLower(strings.TrimSpace(e.Status))
	return s == "error" || s == "failed"
}

// eventID returns a stable, unique id for an event derived from this record. One
// record can emit several events (a message plus a tool call), so the block index
// is folded in. A record id is used when present; otherwise the artifact path and
// line stand in so ids stay deterministic and reproducible.
func (e *copilotEntry) eventID(path string, line, block int) string {
	if id := firstNonEmpty(e.ID, e.EventID, e.MessageID); id != "" {
		return fmt.Sprintf("%s#%d", id, block)
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, block))
	return "copilot-" + hex.EncodeToString(sum[:8])
}
