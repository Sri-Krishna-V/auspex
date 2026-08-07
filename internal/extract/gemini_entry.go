package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Gemini CLI persists two distinct on-disk shapes under
// ~/.gemini/tmp/<project_hash>/, both handled here:
//
//   - logs.json — a whole-file JSON ARRAY of LogEntry objects (see
//     packages/core/src/core/logger.ts). Each entry records ONE user-typed
//     prompt: {sessionId, messageId, timestamp, type:"user", message:"..."}.
//     There is no role, no parts, no functionCall/Response — only the prompt
//     string. This is the auto-saved prompt history.
//   - checkpoint-<tag>.json — a manual /chat save. Current gemini-cli writes a
//     JSON OBJECT {"history": Content[], "authType"?: ...}; legacy versions
//     wrote a bare Content[] array. Both carry the full @google/genai
//     conversation (role + parts), so auspex accepts either shape.
//
// A Content object's role is "user" or "model"; the assistant turn the CLI
// writes uses "model" (the Gemini API role), never "assistant" or "gemini". A
// tool result Content is itself role "user" (the API convention: function
// responses are sent back as a user turn), so role alone does not distinguish a
// human prompt from a tool result — the part KIND does.
const (
	geminiRoleUser  = "user"
	geminiRoleModel = "model"
)

// geminiLogEntryUser is the LogEntry.type value gemini-cli writes for a
// user-typed prompt in logs.json. logs.json records only user prompts, so this
// is the only type auspex maps; any other type is surfaced as a coverage gap
// rather than guessed at.
const geminiLogEntryUser = "user"

// geminiLogEntry is one element of logs.json: a single recorded user prompt.
// Only message and type are decoded — sessionId/messageId/timestamp are
// bookkeeping auspex does not map onto an event field. message is the verbatim
// user-typed prompt string; type is "user" for a prompt (the only kind
// logs.json records).
type geminiLogEntry struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// geminiCheckpoint is the current checkpoint-<tag>.json object shape:
// {"history": Content[], ...}. Only history is decoded; authType and any other
// top-level field are bookkeeping auspex does not map. When a checkpoint file
// is a bare Content[] array instead (legacy gemini-cli), the caller decodes it
// directly into []geminiMessage rather than through this wrapper.
type geminiCheckpoint struct {
	History []geminiMessage `json:"history"`
}

// Gemini CLI tool names (the literal functionCall.name values recorded on disk),
// from packages/core/src/tools/*.ts in google-gemini/gemini-cli. The read-many
// name is retained to suppress returned file content; it otherwise remains a
// generic tool call.
const (
	geminiToolShell     = "run_shell_command"
	geminiToolReadFile  = "read_file"
	geminiToolReadMany  = "read_many_files"
	geminiToolWriteFile = "write_file"
	geminiToolEdit      = "replace" // the edit tool's functionCall name is "replace"
	geminiToolWebFetch  = "web_fetch"
	geminiToolWebSearch = "google_web_search"
)

func geminiToolReturnsFileContent(name string) bool {
	return name == geminiToolReadFile || name == geminiToolReadMany
}

// Gemini CLI functionCall argument keys, from the same source. Auspex reads only
// the fields it maps onto a typed event; everything else in args is ignored.
const (
	geminiArgCommand = "command"   // run_shell_command
	geminiArgFile    = "file_path" // read_file / write_file / replace
	geminiArgPrompt  = "prompt"    // web_fetch (free text carrying the URL)
	geminiArgQuery   = "query"     // google_web_search
)

// geminiMessage is one element of the whole-file conversation array: a
// @google/genai Content. role is "user" or "model"; parts is the ordered list
// of content parts (text, functionCall, functionResponse, and others auspex
// does not model). Only these two fields are decoded so unrelated schema
// additions (e.g. inlineData, thoughtSignature) do not break parsing.
type geminiMessage struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

// geminiPart is a tolerant view of one @google/genai Part. A part is exactly one
// kind: a text part carries Text; a functionCall part carries FunctionCall; a
// functionResponse part carries FunctionResponse. The pointer fields are nil
// when the part is not that kind, which is how the mapper dispatches. Other part
// kinds (inlineData, fileData, executableCode, ...) decode to an all-nil/empty
// part and are skipped rather than guessed at.
type geminiPart struct {
	Text             string                  `json:"text"`
	FunctionCall     *geminiFunctionCall     `json:"functionCall"`
	FunctionResponse *geminiFunctionResponse `json:"functionResponse"`
}

// geminiFunctionCall is a @google/genai FunctionCall part: the tool name, its
// argument map, and an optional id the API uses to correlate the later
// functionResponse. args is kept raw so each tool's well-known keys are decoded
// only when that tool is recognized.
type geminiFunctionCall struct {
	ID   string                     `json:"id"`
	Name string                     `json:"name"`
	Args map[string]json.RawMessage `json:"args"`
}

// geminiFunctionResponse is a @google/genai FunctionResponse part: the name of
// the tool whose result this is, an optional id mirroring the functionCall, and
// the structured response object. response is kept raw so an exit code or error
// flag is read ONLY from a real structured field, never scraped from prose.
type geminiFunctionResponse struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

// geminiArgString returns the string value of a functionCall arg, or "" if the
// arg is absent or not a JSON string. It mirrors inputString for Claude inputs.
func geminiArgString(args map[string]json.RawMessage, key string) string {
	raw, ok := args[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// geminiResponseExitCode lifts a shell exit code from a functionResponse's
// STRUCTURED response object, and only from there. gemini-cli's
// convertToFunctionResponse wraps a tool result in an object; when the shell
// tool records a numeric exit code as a structured field, it is faithful to
// surface it. The well-known key variants are tried in order; a non-numeric or
// absent value yields (0, false) so the caller leaves ExitCode nil rather than
// fabricating a zero "success". The exit code is never parsed out of the free-
// text output body — that would be an inference, not structured evidence.
func geminiResponseExitCode(raw json.RawMessage) (int, bool) {
	obj := decodeJSONObject(raw)
	if obj == nil {
		return 0, false
	}
	for _, key := range []string{"exitCode", "exit_code", "returnCode", "return_code"} {
		v, ok := obj[key]
		if !ok {
			continue
		}
		var n int
		if json.Unmarshal(v, &n) == nil {
			return n, true
		}
	}
	return 0, false
}

// geminiResponseHasError reports whether a functionResponse's STRUCTURED
// response object carries a non-empty error field. gemini-cli records a tool
// failure as a structured "error" (string or object) in the response; auspex
// flags tool_error only on that explicit signal, never inferred from output
// text, an exit code, or a missing field. A present-but-empty error ("", null,
// {}) is treated as no error.
func geminiResponseHasError(raw json.RawMessage) bool {
	obj := decodeJSONObject(raw)
	if obj == nil {
		return false
	}
	v, ok := obj["error"]
	if !ok {
		return false
	}
	trimmed := strings.TrimSpace(string(v))
	switch trimmed {
	case "", "null", `""`, "{}", "[]":
		return false
	}
	return true
}

// geminiResponsePreview lifts a short, human-readable preview from a
// functionResponse's STRUCTURED response object. The well-known content keys
// gemini-cli uses (output for shell, content/result for others) are tried in
// order; a string value is previewed directly. When no known string field is
// present the whole compacted response is previewed, so a result is never an
// empty event. Reads are exempt: the caller does not preview a read result, so
// file content is never stored.
func geminiResponsePreview(raw json.RawMessage) string {
	obj := decodeJSONObject(raw)
	if obj == nil {
		// A non-object response (a bare string/array) is previewed verbatim from
		// its compacted JSON so the result still carries a lead.
		return strings.TrimSpace(string(raw))
	}
	for _, key := range []string{"output", "content", "result", "stdout", "error"} {
		v, ok := obj[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) == nil && s != "" {
			return s
		}
	}
	return strings.TrimSpace(string(raw))
}

// decodeJSONObject decodes raw into a flat key→raw map iff it is a JSON object,
// returning nil for a missing, non-object, or malformed value. It is the single
// guard the response readers share so a scalar/array/null response never yields
// a fabricated field.
func decodeJSONObject(raw json.RawMessage) map[string]json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(trimmed), &obj) != nil {
		return nil
	}
	return obj
}

// geminiEventID returns a stable, unique identifier for an event derived from a
// part at a known position in the whole-file array. The artifact path, the
// message index, the part index, and a sub-index (a single part never emits more
// than one event today, but the slot keeps ids stable if that changes) are
// folded into a hash so ids are deterministic and reproducible across runs and
// never collide between two parts. A functionCall/functionResponse id is NOT
// used as the event id: it correlates a call to its result but is not unique per
// event (a call and its result share it).
func geminiEventID(path string, msgIdx, partIdx, sub int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d:%d", path, msgIdx, partIdx, sub))
	return "gemini-" + hex.EncodeToString(sum[:16])
}
