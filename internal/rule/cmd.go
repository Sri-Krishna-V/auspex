package rule

import (
	"errors"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func cmdWrapperScript(source string, args []*syntax.Word) (string, int, bool, error) {
	for i := 1; i < len(args); i++ {
		flag, ok := staticWord(args[i])
		if !ok {
			return "", 0, false, errors.New("shell command analysis: dynamic cmd option")
		}
		lower := strings.ToLower(flag)
		switch {
		case lower == "/c" || lower == "/k":
			if i+1 >= len(args) {
				return "", 0, false, errors.New("shell command analysis: cmd command option without value")
			}
			script, ok := joinScriptWords(source, args[i+1:])
			if !ok {
				return "", 0, false, errors.New("shell command analysis: dynamic cmd command input")
			}
			return script, i + 1, true, nil
		case lower == "/a" || lower == "/d" || lower == "/q" || lower == "/s" || lower == "/u" ||
			strings.HasPrefix(lower, "/t:") ||
			strings.HasPrefix(lower, "/e:") || strings.HasPrefix(lower, "/f:") || strings.HasPrefix(lower, "/v:"):
			continue
		default:
			if !strings.HasPrefix(flag, "/") {
				return "", 0, false, nil
			}
			return "", 0, false, errors.New("shell command analysis: unsupported cmd option")
		}
	}
	return "", 0, false, nil
}

func (a *shellAnalyzer) parseCMD(source string, depth int, wrappers []ShellWrapper) {
	var (
		segment    strings.Builder
		parenDepth int
		forInDepth int
		quoted     bool
		escaped    bool
		pipelineID int64
	)
	flush := func(relationID int64) {
		value := strings.TrimSpace(segment.String())
		segment.Reset()
		if value != "" {
			a.addCMDSegment(value, depth, wrappers, a.nextStatement(), relationID)
		}
	}

	for i := 0; i < len(source) && !a.halt; i++ {
		c := source[i]
		if escaped {
			segment.WriteByte(c)
			escaped = false
			continue
		}
		if c == '^' {
			segment.WriteByte(c)
			escaped = true
			continue
		}
		if c == '"' {
			segment.WriteByte(c)
			quoted = !quoted
			continue
		}
		if quoted {
			segment.WriteByte(c)
			continue
		}
		if forInDepth > 0 {
			segment.WriteByte(c)
			switch c {
			case '(':
				forInDepth++
			case ')':
				forInDepth--
			}
			continue
		}
		switch c {
		case '(':
			if cmdForInPrefix(segment.String()) {
				segment.WriteByte(c)
				forInDepth = 1
				continue
			}
			flush(pipelineID)
			parenDepth++
			if parenDepth > maxCommandDelimiterDepth {
				a.reportFatal(errors.New("shell command analysis: cmd nesting limit exceeded"))
				return
			}
		case ')':
			flush(pipelineID)
			if parenDepth == 0 {
				a.reportFatal(errors.New("shell command analysis: unsupported or malformed cmd syntax"))
				return
			}
			parenDepth--
		case '&', '|', '\n', '\r':
			if c == '&' && cmdRedirectAmpersand(source, i) {
				segment.WriteByte(c)
				continue
			}
			if c == '|' && (i+1 >= len(source) || source[i+1] != '|') {
				if pipelineID == 0 {
					pipelineID = a.nextPipeline()
				}
				flush(pipelineID)
			} else {
				flush(pipelineID)
				pipelineID = 0
			}
			if (c == '&' || c == '|' || c == '\r') && i+1 < len(source) && source[i+1] == c {
				i++
			}
		default:
			segment.WriteByte(c)
		}
	}
	if a.halt {
		return
	}
	if quoted || escaped || parenDepth != 0 || forInDepth != 0 {
		a.reportFatal(errors.New("shell command analysis: unsupported or malformed cmd syntax"))
		return
	}
	flush(pipelineID)
}

func looksLikeCMDEnvironmentRead(source string) bool {
	if !strings.Contains(source, "%") || !strings.Contains(strings.ToLower(source), "type") {
		return false
	}
	var probe shellAnalyzer
	probe.parseCMD(source, 0, nil)
	for _, command := range probe.commands {
		if command.Name != "type" {
			continue
		}
		for _, argument := range command.Arguments {
			if containsCMDEnvironmentPath(argument.Source) {
				return true
			}
		}
	}
	return false
}

func containsCMDEnvironmentPath(source string) bool {
	for start := 0; start < len(source); start++ {
		if source[start] != '%' {
			continue
		}
		end := strings.IndexByte(source[start+1:], '%')
		if end < 0 {
			break
		}
		end += start + 1
		if validCMDEnvironmentName(source[start+1:end]) &&
			end+1 < len(source) &&
			(source[end+1] == '\\' || source[end+1] == '/') {
			return true
		}
	}
	return false
}

func validCMDEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == '%' || r == '=' {
			return false
		}
	}
	return true
}

func (a *shellAnalyzer) addCMDSegment(segment string, depth int, wrappers []ShellWrapper, statementID, pipelineID int64) {
	segment = trimCMDEchoPrefix(segment)
	if segment == "" {
		return
	}
	lower := strings.ToLower(segment)
	if strings.HasPrefix(lower, "rem ") || lower == "rem" || strings.HasPrefix(segment, "::") || strings.HasPrefix(segment, ":") {
		return
	}
	if lower == "else" {
		return
	}
	if strings.HasPrefix(lower, "else ") {
		a.addCMDSegment(strings.TrimSpace(segment[len("else "):]), depth, wrappers, statementID, pipelineID)
		return
	}
	if strings.HasPrefix(lower, "if ") {
		commands, ok := cmdIfCommands(segment)
		if ok {
			for _, command := range commands {
				a.addCMDSegment(command, depth, wrappers, a.nextStatement(), pipelineID)
			}
		}
		return
	}
	token, _ := firstCommandToken(segment)
	switch strings.ToLower(token) {
	case "for":
		a.report(errors.New("shell command analysis: unsupported dynamic cmd control flow"))
		if body, ok := cmdForBody(segment); ok {
			a.addCMDSegment(body, depth+1, wrappers, a.nextStatement(), pipelineID)
		}
		return
	case "call":
		a.report(errors.New("shell command analysis: dynamic cmd invocation"))
		if depth >= maxCommandExpansionDepth {
			a.report(fmt.Errorf("shell command analysis: expansion nesting exceeds %d", maxCommandExpansionDepth))
			return
		}
		if rest := strings.TrimSpace(segment[len(token):]); rest != "" {
			a.addCMDSegment(rest, depth+1, wrappers, a.nextStatement(), pipelineID)
		}
		return
	}
	if strings.HasPrefix(token, "%") || strings.HasPrefix(token, "!") {
		a.report(errors.New("shell command analysis: dynamic cmd invocation"))
		return
	}
	command, ok, err := projectCMDCommand(segment, wrappers, statementID, pipelineID)
	if err != nil {
		a.report(err)
		return
	}
	if !ok {
		a.report(errors.New("shell command analysis: unsupported or malformed cmd command"))
		return
	}
	if !a.add(command) {
		return
	}
	a.expandProjectedInterpreter(command, depth)
}

func cmdRedirectAmpersand(source string, offset int) bool {
	if offset == 0 || offset+1 >= len(source) {
		return false
	}
	previous, next := source[offset-1], source[offset+1]
	return (previous == '>' || previous == '<') && (next == '-' || next >= '0' && next <= '9')
}

func cmdIfCommands(segment string) ([]string, bool) {
	words := cmdWords(segment)
	if len(words) < 3 || !strings.EqualFold(words[0].text, "if") {
		return nil, false
	}
	i := 1
	if strings.EqualFold(words[i].text, "/i") {
		i++
	}
	if i < len(words) && strings.EqualFold(words[i].text, "not") {
		i++
	}
	if i >= len(words) {
		return nil, false
	}
	switch strings.ToLower(words[i].text) {
	case "exist", "defined", "errorlevel", "cmdextversion":
		i += 2
	default:
		if strings.Contains(words[i].text, "==") {
			i++
		} else {
			if i+2 >= len(words) {
				return nil, false
			}
			i += 3
		}
	}
	if i >= len(words) {
		return nil, false
	}
	thenStart := words[i].start
	for j := i + 1; j < len(words); j++ {
		if strings.EqualFold(words[j].text, "else") {
			thenCommand := strings.TrimSpace(segment[thenStart:words[j].start])
			elseCommand := strings.TrimSpace(segment[words[j].end:])
			if thenCommand == "" || elseCommand == "" {
				return nil, false
			}
			return []string{thenCommand, elseCommand}, true
		}
	}
	return []string{strings.TrimSpace(segment[thenStart:])}, true
}

type cmdWord struct {
	text  string
	start int
	end   int
}

func cmdWords(source string) []cmdWord {
	var words []cmdWord
	for i := 0; i < len(source); {
		for i < len(source) && (source[i] == ' ' || source[i] == '\t') {
			i++
		}
		if i >= len(source) {
			break
		}
		start := i
		var value strings.Builder
		quoted := false
		for i < len(source) {
			c := source[i]
			if c == '^' && i+1 < len(source) {
				value.WriteByte(source[i+1])
				i += 2
				continue
			}
			if c == '"' {
				quoted = !quoted
				i++
				continue
			}
			if !quoted && (c == ' ' || c == '\t') {
				break
			}
			value.WriteByte(c)
			i++
		}
		words = append(words, cmdWord{text: value.String(), start: start, end: i})
	}
	return words
}

func projectCMDArgument(source string, word cmdWord) ShellArgument {
	spelling := source[word.start:word.end]
	var (
		quoted    bool
		sawQuoted bool
		sawBare   bool
	)
	for i := 0; i < len(spelling); i++ {
		switch spelling[i] {
		case '^':
			if i+1 < len(spelling) {
				i++
				if quoted {
					sawQuoted = true
				} else {
					sawBare = true
				}
			}
		case '"':
			quoted = !quoted
		default:
			if quoted {
				sawQuoted = true
			} else {
				sawBare = true
			}
		}
	}
	quote := quoteNone
	if sawQuoted && !sawBare {
		quote = quoteDouble
	} else if sawQuoted {
		quote = quoteMixed
	}
	return ShellArgument{
		Value:   word.text,
		Source:  spelling,
		Quote:   quote,
		Expands: cmdArgumentExpands(spelling),
	}
}

func cmdArgumentExpands(source string) bool {
	for i := 0; i < len(source); i++ {
		if source[i] == '^' && i+1 < len(source) {
			i++
			continue
		}
		if source[i] != '%' && source[i] != '!' {
			continue
		}
		if source[i] == '%' && i+1 < len(source) {
			next := source[i+1]
			if next == '*' || next == '~' || next == '%' || next >= '0' && next <= '9' {
				return true
			}
			if next >= 'a' && next <= 'z' || next >= 'A' && next <= 'Z' {
				return true
			}
		}
		if strings.IndexByte(source[i+1:], source[i]) >= 0 {
			return true
		}
	}
	return false
}

func cmdForInPrefix(segment string) bool {
	words := cmdWords(trimCMDEchoPrefix(segment))
	return len(words) >= 3 && strings.EqualFold(words[0].text, "for") &&
		strings.EqualFold(words[len(words)-1].text, "in")
}

func cmdForBody(segment string) (string, bool) {
	words := cmdWords(segment)
	for i := 1; i < len(words); i++ {
		if strings.EqualFold(words[i].text, "do") {
			body := strings.TrimSpace(segment[words[i].end:])
			return body, body != ""
		}
	}
	return "", false
}

func projectCMDCommand(segment string, wrappers []ShellWrapper, statementID, pipelineID int64) (ShellCommand, bool, error) {
	segment = trimCMDEchoPrefix(segment)
	commandSource, redirects, err := projectCMDRedirects(segment)
	if err != nil {
		return ShellCommand{}, false, err
	}
	words := cmdWords(commandSource)
	if len(words) == 0 {
		if len(redirects) == 0 {
			return ShellCommand{}, false, nil
		}
		return ShellCommand{
			Redirects:   redirects,
			Dialect:     dialectCMD.String(),
			Wrappers:    cloneWrappers(wrappers),
			StatementID: statementID,
			PipelineID:  pipelineID,
			Preview:     previewNormal,
		}, true, nil
	}
	if words[0].text == "" {
		return ShellCommand{}, false, nil
	}
	argv := make([]string, len(words))
	arguments := make([]ShellArgument, len(words))
	for i, word := range words {
		argv[i] = word.text
		arguments[i] = projectCMDArgument(commandSource, word)
	}
	return ShellCommand{
		Executable:  argv[0],
		Name:        commandProgram(argv[0]),
		Argv:        argv,
		Arguments:   arguments,
		Redirects:   redirects,
		Dialect:     dialectCMD.String(),
		Wrappers:    cloneWrappers(wrappers),
		StatementID: statementID,
		PipelineID:  pipelineID,
		Preview:     previewNormal,
	}, true, nil
}

func trimCMDEchoPrefix(source string) string {
	source = strings.TrimSpace(source)
	for strings.HasPrefix(source, "@") {
		source = strings.TrimSpace(source[1:])
	}
	return source
}

func projectCMDRedirects(source string) (string, []ShellRedirect, error) {
	var (
		command   strings.Builder
		redirects []ShellRedirect
		quoted    bool
	)
	for i := 0; i < len(source); {
		if source[i] == '^' && i+1 < len(source) {
			command.WriteString(source[i : i+2])
			i += 2
			continue
		}
		if source[i] == '"' {
			quoted = !quoted
			command.WriteByte(source[i])
			i++
			continue
		}
		if quoted {
			command.WriteByte(source[i])
			i++
			continue
		}

		fd, operatorAt, matched := cmdRedirectOperator(source, i)
		if !matched {
			command.WriteByte(source[i])
			i++
			continue
		}
		op := redirectWrite
		operatorEnd := operatorAt + 1
		if source[operatorAt] == '<' {
			fd, op = 0, redirectRead
		} else if operatorEnd < len(source) && source[operatorEnd] == '>' {
			op = redirectAppend
			operatorEnd++
		}
		targetStart := operatorEnd
		for targetStart < len(source) && (source[targetStart] == ' ' || source[targetStart] == '\t') {
			targetStart++
		}
		targetEnd := cmdRedirectTargetEnd(source, targetStart)
		if targetStart == targetEnd {
			return "", nil, errors.New("shell command analysis: cmd redirect without target")
		}
		targetWords := cmdWords(source[targetStart:targetEnd])
		if len(targetWords) != 1 || targetWords[0].text == "" {
			return "", nil, errors.New("shell command analysis: unsupported cmd redirect target")
		}
		redirect, err := windowsRedirect(fd, op, projectCMDArgument(source[targetStart:targetEnd], targetWords[0]))
		if err != nil {
			return "", nil, err
		}
		redirects = append(redirects, redirect)
		if command.Len() > 0 {
			command.WriteByte(' ')
		}
		i = targetEnd
	}
	if quoted {
		return "", nil, errors.New("shell command analysis: unsupported or malformed cmd syntax")
	}
	return strings.TrimSpace(command.String()), redirects, nil
}

func cmdRedirectOperator(source string, offset int) (int64, int, bool) {
	if offset >= len(source) {
		return 0, 0, false
	}
	if source[offset] == '>' {
		return 1, offset, true
	}
	if source[offset] == '<' {
		return 0, offset, true
	}
	if source[offset] >= '0' && source[offset] <= '9' && offset+1 < len(source) &&
		(source[offset+1] == '>' || source[offset+1] == '<') {
		return int64(source[offset] - '0'), offset + 1, true
	}
	return 0, 0, false
}

func cmdRedirectTargetEnd(source string, start int) int {
	if start >= len(source) {
		return start
	}
	if source[start] == '&' {
		if start+1 < len(source) && (source[start+1] == '-' || source[start+1] >= '0' && source[start+1] <= '9') {
			return start + 2
		}
		return start
	}
	quoted := false
	for i := start; i < len(source); i++ {
		switch source[i] {
		case '^':
			if i+1 < len(source) {
				i++
			}
		case '"':
			quoted = !quoted
		case ' ', '\t':
			if !quoted {
				return i
			}
		}
	}
	if quoted {
		return start
	}
	return len(source)
}
