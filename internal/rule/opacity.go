package rule

import (
	"strings"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// opacityMarkerOrder is the canonical report order for opacity reasons. Two
// endpoints observing the same command must emit the same array, so the order
// is fixed here rather than following the order markers happen to be found in.
var opacityMarkerOrder = []string{
	model.OpacityDetached,
	model.OpacityDynamicArgument,
	model.OpacityEncodedPayload,
	model.OpacityInlineInterpreter,
	model.OpacityPipedToInterpreter,
}

// opacityInterpreters are programs that will execute a program handed to them
// rather than one named on disk. Matched on the basename projection, so
// /usr/bin/python3 and python3 are the same program.
var opacityInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "node": true, "nodejs": true, "php": true,
	"powershell": true, "pwsh": true, "osascript": true, "cmd": true,
}

// opacityDecoders are programs whose output is bytes that were never present in
// the observed command text. openssl and certutil decode only under a
// subcommand, so they are matched on the argument rather than the name.
var opacityDecoders = map[string]bool{
	"base64": true, "xxd": true, "uudecode": true, "base32": true,
}

var opacityDecoderSubcommands = map[string][]string{
	"openssl":  {"enc"},
	"certutil": {"-decode", "-decodehex"},
}

// opacityDetachers are launchers that outlive the session auspex observed.
//
// ponytail: basename-only. A trailing `&` is a parser property (syntax.Stmt.Background)
// that ShellCommand does not retain; add it there if backgrounding needs its own signal.
var opacityDetachers = map[string]bool{
	"nohup": true, "setsid": true, "disown": true,
}

// Opacity reports the markers explaining why the effect of ev's command cannot
// be read from the command text, and whether the command was analyzed at all.
//
// The second return is the honesty boundary. An empty reason list with
// analyzed=true is a real claim — auspex parsed the command and saw everything
// it does. analyzed=false means auspex could not read the command at all (it
// carries none, or the command was unparseable, oversize, or in a dialect the
// analyzer cannot project), and the caller must leave the score absent rather
// than record a 0 it cannot support. POSIX shell, PowerShell, and cmd.exe are
// all projectable, so a foreign-looking command is not automatically unscored.
//
// ponytail: no cross-event markers; add as a sequence rule if write-then-exec needs its own signal.
func Opacity(ev model.Event) ([]string, bool) {
	if strings.TrimSpace(ev.Command) == "" {
		return nil, false
	}
	commands, usable, _ := analyzeEventShellCommands(ev)
	if !usable {
		return nil, false
	}

	found := make(map[string]bool, model.OpacityReasonCount)
	firstInPipeline := firstPipelineStatements(commands)
	for i := range commands {
		command := commands[i]
		switch {
		case opacityDetachers[command.Name]:
			found[model.OpacityDetached] = true
		case opacityDecoders[command.Name], hasAnyArgument(command, opacityDecoderSubcommands[command.Name]):
			found[model.OpacityEncodedPayload] = true
		}
		if inlineInterpreter(command) {
			found[model.OpacityInlineInterpreter] = true
		}
		if opacityInterpreters[command.Name] && command.PipelineID != 0 &&
			firstInPipeline[command.PipelineID] != command.StatementID && !hasScriptOperand(command) {
			found[model.OpacityPipedToInterpreter] = true
		}
		if dynamicCommand(command) {
			found[model.OpacityDynamicArgument] = true
		}
	}

	var reasons []string
	for _, marker := range opacityMarkerOrder {
		if found[marker] {
			reasons = append(reasons, marker)
		}
	}
	return reasons, true
}

// firstPipelineStatements maps each pipeline to its leading statement. Commands
// are projected in source order within a walk, so the lowest statement id in a
// pipeline is the stage that produces rather than consumes.
func firstPipelineStatements(commands []ShellCommand) map[int64]int64 {
	first := make(map[int64]int64)
	for i := range commands {
		id := commands[i].PipelineID
		if id == 0 {
			continue
		}
		if existing, ok := first[id]; !ok || commands[i].StatementID < existing {
			first[id] = commands[i].StatementID
		}
	}
	return first
}

// inlineInterpreter reports whether the command hands its program to the
// interpreter in the argv. The accepted option differs per interpreter family:
// -e means errexit to a shell and eval to perl, so one shared flag set would
// report a marker for `bash -e deploy.sh`.
func inlineInterpreter(command ShellCommand) bool {
	if !opacityInterpreters[command.Name] {
		return false
	}
	for i := 1; i < len(command.Arguments); i++ {
		flag := command.Arguments[i].Value
		switch command.Name {
		case "sh", "bash", "dash", "zsh", "ksh", "mksh":
			if isShellCommandFlag(flag) {
				return true
			}
		case "powershell", "pwsh":
			name, _, _ := strings.Cut(strings.ToLower(flag), ":")
			switch name {
			case "-c", "-command", "-commandwithargs", "-cwa",
				"-e", "-ec", "-enc", "-encodedcommand":
				return true
			}
		case "cmd":
			switch strings.ToLower(flag) {
			case "/c", "/k":
				return true
			}
		default:
			if flag == "-c" || flag == "-e" || flag == "--eval" {
				return true
			}
		}
	}
	return false
}

// hasScriptOperand reports whether the interpreter was given a program to read
// from disk. Words after `--` are positional parameters for the program, not a
// program, so they do not count.
func hasScriptOperand(command ShellCommand) bool {
	for i := 1; i < len(command.Arguments); i++ {
		value := command.Arguments[i].Value
		if value == "--" {
			return false
		}
		if !strings.HasPrefix(value, "-") {
			return true
		}
	}
	return false
}

func hasAnyArgument(command ShellCommand, want []string) bool {
	if len(want) == 0 {
		return false
	}
	for i := 1; i < len(command.Arguments); i++ {
		value := strings.ToLower(command.Arguments[i].Value)
		for _, candidate := range want {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

// dynamicCommand reuses the three properties commandSafeForEnforcement already
// derives for the enforcement gate: a word, a redirect target, or a callee that
// the parser proved is not what it appears to be. It deliberately does not reuse
// the whole predicate, whose other clauses fire on every inline script and would
// make this marker redundant with inline_interpreter.
func dynamicCommand(command ShellCommand) bool {
	if command.FunctionCall {
		return true
	}
	for _, argument := range command.Arguments {
		if argument.Expands {
			return true
		}
	}
	for _, redirect := range command.Redirects {
		if redirect.TargetExpands {
			return true
		}
	}
	return false
}
