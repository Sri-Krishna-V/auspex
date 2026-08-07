package extract

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// Codex code mode persists one JavaScript cell as a custom tool call. Promote
// only common, unambiguous static calls; arbitrary programs stay generic.
var (
	codexCodeModeExecPrefix       = regexp.MustCompile(`^const[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)[[:space:]]*=[[:space:]]*await[[:space:]]+tools\.exec_command[[:space:]]*\([[:space:]]*`)
	codexCodeModeWriteStdinPrefix = regexp.MustCompile(`^const[[:space:]]+([A-Za-z_$][A-Za-z0-9_$]*)[[:space:]]*=[[:space:]]*await[[:space:]]+tools\.write_stdin[[:space:]]*\([[:space:]]*`)
)

const codexCodeModeStringToken = "<string>"

type codexCodeModeResultKind uint8

const (
	codexCodeModeResultNone codexCodeModeResultKind = iota
	codexCodeModeResultOutput
	codexCodeModeResultObject
)

type codexCodeModeExec struct {
	command    string
	resultKind codexCodeModeResultKind
}

type codexCodeModeOutcome struct {
	output     string
	exitCode   *int
	durationMs *int64
	cellID     string
	sessionID  string
	toolError  bool
	recognized bool
}

type codexCodeModeResultRef struct {
	commandCallID string
	resultKind    codexCodeModeResultKind
	sessionID     string
	sessionPoll   bool
}

type codexCodeModeTracker struct {
	customCalls map[string]codexCodeModeResultRef
	waitCalls   map[string]codexCodeModeResultRef
	cells       map[string]codexCodeModeResultRef
	sessions    map[string]codexCodeModeResultRef
}

func codexCodeModeExecCommand(input string) (string, bool) {
	call, ok := parseCodexCodeModeExec(input)
	return call.command, ok
}

func parseCodexCodeModeExec(input string) (codexCodeModeExec, bool) {
	args, resultKind, ok := parseCodexCodeModeStaticCall(input, codexCodeModeExecPrefix)
	if !ok {
		return codexCodeModeExec{}, false
	}
	command, ok := args["cmd"].(string)
	if !ok || strings.TrimSpace(command) == "" {
		return codexCodeModeExec{}, false
	}
	return codexCodeModeExec{command: command, resultKind: resultKind}, true
}

func parseCodexCodeModeWriteStdinPoll(input string) (sessionID string, resultKind codexCodeModeResultKind, ok bool) {
	args, resultKind, ok := parseCodexCodeModeStaticCall(input, codexCodeModeWriteStdinPrefix)
	if !ok || resultKind == codexCodeModeResultNone {
		return "", codexCodeModeResultNone, false
	}
	if chars, exists := args["chars"]; exists {
		text, isString := chars.(string)
		if !isString || text != "" {
			return "", codexCodeModeResultNone, false
		}
	}
	sessionID, ok = codexCodeModeStaticID(args["session_id"])
	return sessionID, resultKind, ok
}

func parseCodexCodeModeStaticCall(input string, prefix *regexp.Regexp) (map[string]any, codexCodeModeResultKind, bool) {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "// @exec:") {
		newline := strings.IndexByte(s, '\n')
		if newline < 0 {
			return nil, codexCodeModeResultNone, false
		}
		s = strings.TrimSpace(s[newline+1:])
	}

	match := prefix.FindStringSubmatchIndex(s)
	if match == nil || !isCodexCodeModeBindingName(s[match[2]:match[3]]) {
		return nil, codexCodeModeResultNone, false
	}
	resultName := s[match[2]:match[3]]

	args, end, ok := parseCodexCodeModeArgs(s, match[1])
	if !ok {
		return nil, codexCodeModeResultNone, false
	}
	end = skipASCIIWhitespace(s, end)
	if end >= len(s) || s[end] != ')' {
		return nil, codexCodeModeResultNone, false
	}
	end++
	var lineBreak bool
	end, lineBreak = skipCodexCodeModeStatementSpace(s, end)
	separated := lineBreak
	if end < len(s) && s[end] == ';' {
		end++
		separated = true
	}
	if skipASCIIWhitespace(s, end) < len(s) && !separated {
		return nil, codexCodeModeResultNone, false
	}

	// Accept only an empty tail or the common result-forwarding forms. Any other
	// JavaScript may contain another operation or alter the meaning of the output.
	resultKind, ok := codexCodeModeResultTail(s[end:], resultName)
	if !ok {
		return nil, codexCodeModeResultNone, false
	}
	return args, resultKind, true
}

func codexCodeModeResultTail(s, resultName string) (codexCodeModeResultKind, bool) {
	tokens, ok := codexCodeModeTailTokens(s)
	if !ok {
		return codexCodeModeResultNone, false
	}
	if len(tokens) == 0 {
		return codexCodeModeResultNone, true
	}
	if tokens[len(tokens)-1] == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	// These declarations shadow helpers used by the corresponding tail shape.
	if resultName == "text" {
		return codexCodeModeResultNone, false
	}
	if codexCodeModeTokensEqual(tokens, "text", "(", resultName, ")") {
		return codexCodeModeResultObject, true
	}
	if codexCodeModeTokensEqual(tokens, "text", "(", resultName, ".", "output", ")") ||
		codexCodeModeTokensEqual(tokens, "text", "(", resultName, ".", "output", "||", codexCodeModeStringToken, ")") {
		return codexCodeModeResultOutput, true
	}
	if resultName != "JSON" && codexCodeModeTokensEqual(tokens,
		"text", "(", "JSON", ".", "stringify", "(", resultName, ")", ")") {
		return codexCodeModeResultObject, true
	}
	return codexCodeModeResultNone, false
}

var (
	codexCodeModeOutputEnvelope   = regexp.MustCompile(`^Script completed\nWall time [0-9]+(?:\.[0-9]+)? seconds\nOutput:\n$`)
	codexCodeModeFailedEnvelope   = regexp.MustCompile(`^Script failed\nWall time [0-9]+(?:\.[0-9]+)? seconds\nOutput:\n$`)
	codexCodeModeRunningEnvelope  = regexp.MustCompile(`^Script running with cell ID ([^\n]+)\nWall time [0-9]+(?:\.[0-9]+)? seconds\nOutput:\n$`)
	codexCodeModeTruncationPrefix = regexp.MustCompile(`^Warning: truncated output \(original token count: [0-9]+\)\nTotal output lines: [0-9]+\n\n`)
)

func decodeCodexCodeModeOutput(raw json.RawMessage) (string, bool) {
	return decodeCodexCodeModeEnvelope(raw, codexCodeModeOutputEnvelope)
}

func decodeCodexCodeModeEnvelope(raw json.RawMessage, envelope *regexp.Regexp) (string, bool) {
	var items []codexContentItem
	if json.Unmarshal(raw, &items) != nil || len(items) != 2 ||
		items[0].Type != "input_text" || items[1].Type != "input_text" ||
		!envelope.MatchString(items[0].Text) {
		return "", false
	}
	return items[1].Text, true
}

func decodeCodexCodeModeOutcome(raw json.RawMessage, kind codexCodeModeResultKind) codexCodeModeOutcome {
	outcome := codexCodeModeOutcome{
		output:     decodeCodexOutput(raw),
		recognized: kind != codexCodeModeResultObject,
	}
	// A running cell is a plain control envelope. Completed command stdout is
	// carried in separate content items, so it cannot impersonate this shape.
	if cellID, ok := codexCodeModeRunningCellID(raw); ok {
		outcome.cellID = cellID
		outcome.recognized = true
		return outcome
	}
	if body, ok := decodeCodexCodeModeEnvelope(raw, codexCodeModeFailedEnvelope); ok {
		outcome.output = body
		outcome.toolError = true
		outcome.recognized = true
		return outcome
	}
	if body, ok := decodeCodexCodeModeOutput(raw); ok {
		outcome.output = body
	}
	if kind != codexCodeModeResultObject {
		return outcome
	}

	body, exitCode, durationMs, sessionID, ok := decodeCodexCodeModeResultObject(raw)
	if !ok {
		return outcome
	}
	outcome.output = body
	outcome.exitCode = exitCode
	outcome.durationMs = durationMs
	outcome.sessionID = sessionID
	outcome.toolError = exitCode != nil && *exitCode != 0
	outcome.recognized = true
	return outcome
}

func decodeCodexCodeModeResultObject(raw json.RawMessage) (output string, exitCode *int, durationMs *int64, sessionID string, ok bool) {
	body, ok := decodeCodexCodeModeOutput(raw)
	if !ok {
		return "", nil, nil, "", false
	}
	body = codexCodeModeTruncationPrefix.ReplaceAllString(body, "")
	var result struct {
		ExitCode        *int            `json:"exit_code"`
		Output          *string         `json:"output"`
		SessionID       json.RawMessage `json:"session_id"`
		WallTimeSeconds *float64        `json:"wall_time_seconds"`
	}
	if json.Unmarshal([]byte(body), &result) != nil || result.Output == nil {
		return "", nil, nil, "", false
	}
	if len(result.SessionID) > 0 && string(result.SessionID) != "null" {
		var valid bool
		sessionID, valid = codexCodeModeRawID(result.SessionID)
		if !valid {
			return "", nil, nil, "", false
		}
	}
	if result.ExitCode != nil && result.WallTimeSeconds != nil &&
		*result.WallTimeSeconds >= 0 && *result.WallTimeSeconds < float64(math.MaxInt64/1000) {
		milliseconds := int64(math.Round(*result.WallTimeSeconds * 1000))
		durationMs = &milliseconds
	}
	return *result.Output, result.ExitCode, durationMs, sessionID, true
}

func codexCodeModeRawID(raw json.RawMessage) (string, bool) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return "", false
	}
	return codexCodeModeStaticID(value)
}

func codexCodeModeRunningCellID(raw json.RawMessage) (string, bool) {
	var output string
	if json.Unmarshal(raw, &output) != nil {
		return "", false
	}
	match := codexCodeModeRunningEnvelope.FindStringSubmatch(output)
	if len(match) != 2 || strings.TrimSpace(match[1]) == "" {
		return "", false
	}
	return match[1], true
}

func (t *codexCodeModeTracker) noteExec(callID string, resultKind codexCodeModeResultKind) {
	if callID == "" {
		return
	}
	if t.customCalls == nil {
		t.customCalls = make(map[string]codexCodeModeResultRef)
	}
	t.customCalls[callID] = codexCodeModeResultRef{
		commandCallID: callID,
		resultKind:    resultKind,
	}
}

func (t *codexCodeModeTracker) noteWriteStdinPoll(callID, input string) bool {
	if callID == "" {
		return false
	}
	sessionID, resultKind, ok := parseCodexCodeModeWriteStdinPoll(input)
	if !ok {
		return false
	}
	ref, ok := t.sessions[sessionID]
	if !ok {
		return false
	}
	ref.resultKind = resultKind
	ref.sessionPoll = true
	ref.sessionID = sessionID
	if t.customCalls == nil {
		t.customCalls = make(map[string]codexCodeModeResultRef)
	}
	t.customCalls[callID] = ref
	return true
}

func (t *codexCodeModeTracker) noteWait(callID, arguments string) bool {
	if callID == "" {
		return false
	}
	cellID, terminate, ok := codexCodeModeWaitCellID(arguments)
	if !ok {
		return false
	}
	if terminate {
		delete(t.cells, cellID)
		return false
	}
	ref, ok := t.cells[cellID]
	if !ok {
		return false
	}
	delete(t.cells, cellID)
	if t.waitCalls == nil {
		t.waitCalls = make(map[string]codexCodeModeResultRef)
	}
	t.waitCalls[callID] = ref
	return true
}

func (t *codexCodeModeTracker) forgetCall(callID string) {
	delete(t.customCalls, callID)
	delete(t.waitCalls, callID)
	forgetCodexCodeModeOwner(t.customCalls, callID)
	forgetCodexCodeModeOwner(t.waitCalls, callID)
	forgetCodexCodeModeOwner(t.cells, callID)
	forgetCodexCodeModeOwner(t.sessions, callID)
}

func forgetCodexCodeModeOwner(entries map[string]codexCodeModeResultRef, callID string) {
	for id, ref := range entries {
		if ref.commandCallID == callID {
			delete(entries, id)
		}
	}
}

func (t *codexCodeModeTracker) takeCustomCall(callID string) (codexCodeModeResultRef, bool) {
	ref, ok := t.customCalls[callID]
	delete(t.customCalls, callID)
	return ref, ok
}

func (t *codexCodeModeTracker) takeWaitCall(callID string) (codexCodeModeResultRef, bool) {
	ref, ok := t.waitCalls[callID]
	delete(t.waitCalls, callID)
	return ref, ok
}

func (t *codexCodeModeTracker) trackOutcome(ref codexCodeModeResultRef, raw json.RawMessage) codexCodeModeOutcome {
	outcome := decodeCodexCodeModeOutcome(raw, ref.resultKind)
	if outcome.cellID != "" {
		if t.cells == nil {
			t.cells = make(map[string]codexCodeModeResultRef)
		}
		t.cells[outcome.cellID] = ref
	}
	if outcome.sessionID != "" {
		if ref.sessionID != "" && ref.sessionID != outcome.sessionID {
			delete(t.sessions, ref.sessionID)
		}
		if t.sessions == nil {
			t.sessions = make(map[string]codexCodeModeResultRef)
		}
		next := ref
		next.sessionPoll = true
		next.sessionID = outcome.sessionID
		t.sessions[outcome.sessionID] = next
	}
	if outcome.exitCode != nil || outcome.toolError {
		if ref.sessionID != "" {
			delete(t.sessions, ref.sessionID)
		}
		if outcome.sessionID != "" {
			delete(t.sessions, outcome.sessionID)
		}
	}
	if ref.sessionPoll {
		outcome.durationMs = nil
	}
	return outcome
}

func codexCodeModeWaitCellID(arguments string) (cellID string, terminate bool, ok bool) {
	var args map[string]json.RawMessage
	if json.Unmarshal([]byte(arguments), &args) != nil {
		return "", false, false
	}
	if raw, exists := args["terminate"]; exists {
		if json.Unmarshal(raw, &terminate) != nil {
			return "", false, false
		}
	}
	cellID, ok = codexCodeModeRawID(args["cell_id"])
	return cellID, terminate, ok
}

func codexCodeModeTailTokens(s string) ([]string, bool) {
	var tokens []string
	for i := 0; ; {
		i = skipASCIIWhitespace(s, i)
		if i == len(s) {
			return tokens, true
		}
		if isJSIdentifierStart(s[i]) {
			end := i + 1
			for end < len(s) && isJSIdentifierContinue(s[end]) {
				end++
			}
			tokens = append(tokens, s[i:end])
			i = end
			continue
		}
		if s[i] == '"' {
			var value string
			decoder := json.NewDecoder(strings.NewReader(s[i:]))
			if err := decoder.Decode(&value); err != nil || decoder.InputOffset() <= 0 {
				return nil, false
			}
			tokens = append(tokens, codexCodeModeStringToken)
			i += int(decoder.InputOffset())
			continue
		}
		if strings.HasPrefix(s[i:], "||") {
			tokens = append(tokens, "||")
			i += 2
			continue
		}
		switch s[i] {
		case '(', ')', '.', ';':
			tokens = append(tokens, s[i:i+1])
			i++
		default:
			return nil, false
		}
	}
}

func codexCodeModeTokensEqual(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func parseCodexCodeModeArgs(s string, start int) (map[string]any, int, bool) {
	i := skipASCIIWhitespace(s, start)
	if i >= len(s) || s[i] != '{' {
		return nil, 0, false
	}
	i++

	args := make(map[string]any)
	for {
		i = skipASCIIWhitespace(s, i)
		if i >= len(s) {
			return nil, 0, false
		}
		if s[i] == '}' {
			return args, i + 1, true
		}

		key, next, ok := parseCodexCodeModePropertyName(s, i)
		if !ok {
			return nil, 0, false
		}
		if _, duplicate := args[key]; duplicate {
			return nil, 0, false
		}
		i = skipASCIIWhitespace(s, next)
		if i >= len(s) || s[i] != ':' {
			return nil, 0, false
		}
		i = skipASCIIWhitespace(s, i+1)

		var value any
		decoder := json.NewDecoder(strings.NewReader(s[i:]))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil || decoder.InputOffset() <= 0 {
			return nil, 0, false
		}
		i += int(decoder.InputOffset())
		args[key] = value

		i = skipASCIIWhitespace(s, i)
		if i >= len(s) {
			return nil, 0, false
		}
		switch s[i] {
		case '}':
			return args, i + 1, true
		case ',':
			i++
			if next := skipASCIIWhitespace(s, i); next < len(s) && s[next] == '}' {
				return args, next + 1, true
			}
		default:
			return nil, 0, false
		}
	}
}

func codexCodeModeStaticID(value any) (string, bool) {
	switch value := value.(type) {
	case json.Number:
		if _, err := value.Int64(); err == nil {
			return value.String(), true
		}
	case string:
		if strings.TrimSpace(value) != "" {
			return value, true
		}
	}
	return "", false
}

func parseCodexCodeModePropertyName(s string, start int) (string, int, bool) {
	if start >= len(s) {
		return "", 0, false
	}
	if s[start] == '"' {
		var key string
		decoder := json.NewDecoder(strings.NewReader(s[start:]))
		if err := decoder.Decode(&key); err != nil || decoder.InputOffset() <= 0 {
			return "", 0, false
		}
		return key, start + int(decoder.InputOffset()), true
	}
	if !isJSIdentifierStart(s[start]) {
		return "", 0, false
	}
	end := start + 1
	for end < len(s) && isJSIdentifierContinue(s[end]) {
		end++
	}
	return s[start:end], end, true
}

func isJSIdentifierStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$'
}

func isJSIdentifierContinue(c byte) bool {
	return isJSIdentifierStart(c) || c >= '0' && c <= '9'
}

func isCodexCodeModeBindingName(name string) bool {
	switch name {
	case "await", "break", "case", "catch", "class", "const", "continue",
		"debugger", "default", "delete", "do", "else", "enum", "eval",
		"export", "extends", "false", "finally", "for", "function", "if",
		"implements", "import", "in", "instanceof", "interface", "let", "new",
		"null", "package", "private", "protected", "public", "return", "static",
		"super", "switch", "this", "throw", "tools", "true", "try", "typeof",
		"var", "void", "while", "with", "yield", "arguments":
		return false
	default:
		return true
	}
}

func skipASCIIWhitespace(s string, start int) int {
	for start < len(s) {
		switch s[start] {
		case ' ', '\t', '\r', '\n', '\f':
			start++
		default:
			return start
		}
	}
	return start
}

func skipCodexCodeModeStatementSpace(s string, start int) (int, bool) {
	lineBreak := false
	for start < len(s) {
		switch s[start] {
		case '\r', '\n':
			lineBreak = true
			start++
		case ' ', '\t', '\f':
			start++
		default:
			return start, lineBreak
		}
	}
	return start, lineBreak
}
