package rule

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func posixEnforcementShapeSafe(file *syntax.File) bool {
	return file != nil && len(file.Stmts) == 1 && posixStatementEnforcementSafe(file.Stmts[0])
}

func posixStatementEnforcementSafe(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Hdoc != nil {
			return false
		}
	}
	switch command := stmt.Cmd.(type) {
	case nil:
		return len(stmt.Redirs) > 0
	case *syntax.CallExpr:
		return true
	case *syntax.BinaryCmd:
		if command.Op != syntax.Pipe && command.Op != syntax.PipeAll {
			return false
		}
		return posixStatementEnforcementSafe(command.X) &&
			posixStatementEnforcementSafe(command.Y)
	default:
		return false
	}
}

func powerShellEnforcementShapeSafe(source string) bool {
	var singleQuoted, doubleQuoted bool
	for i := 0; i < len(source); i++ {
		switch {
		case singleQuoted:
			if source[i] == '\'' {
				if i+1 < len(source) && source[i+1] == '\'' {
					i++
				} else {
					singleQuoted = false
				}
			}
		case doubleQuoted:
			switch source[i] {
			case '`':
				return false
			case '"':
				doubleQuoted = false
			}
		default:
			switch source[i] {
			case '\'':
				singleQuoted = true
			case '"':
				doubleQuoted = true
			case '&':
				if !cmdRedirectAmpersand(source, i) {
					return false
				}
			case '`', ';', ',', '\n', '\r', '|', '(', ')', '{', '}', '[', ']':
				return false
			}
		}
	}
	return !singleQuoted && !doubleQuoted
}

func cmdEnforcementShapeSafe(source string) bool {
	source = trimCMDEchoPrefix(source)
	var quoted bool
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case '^':
			return false
		case '"':
			quoted = !quoted
		case '&':
			if !quoted && !cmdRedirectAmpersand(source, i) {
				return false
			}
		case '|', '(', ')', '\n', '\r':
			if !quoted {
				return false
			}
		}
	}
	if quoted {
		return false
	}
	words := cmdWords(source)
	if len(words) == 0 {
		return false
	}
	switch commandProgram(strings.ToLower(words[0].text)) {
	case "call", "else", "endlocal", "exit", "for", "goto", "if", "set",
		"setlocal", "start":
		return false
	default:
		return true
	}
}
