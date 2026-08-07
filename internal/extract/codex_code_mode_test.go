package extract

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func TestExtractCodexCodeModeCommandAndResult(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"printf 'hello\\n'", workdir:"/tmp", yield_time_ms:10000, max_output_tokens:2000}); text(r.output);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":"hello"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2: %s", len(acts), dumpEvents(acts))
	}
	call, result := acts[0], acts[1]
	if call.EventType != model.EventCommandExec || call.Command != "printf 'hello\\n'" || call.ToolName != codexToolExecCommand {
		t.Errorf("call = %+v, want one decoded command.exec", call)
	}
	if result.EventType != model.EventCommandResult || result.ToolCallID != call.ToolCallID || result.ContentPreview != "hello" {
		t.Errorf("result = %+v, want correlated command.result", result)
	}
	if call.Evidence.JSONPointer != "/payload/input" {
		t.Errorf("call evidence pointer = %q, want /payload/input", call.Evidence.JSONPointer)
	}
}

func TestExtractCodexCodeModeStructuredResult(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"false"}); text(JSON.stringify(r));`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":[{"type":"input_text","text":"Script completed\nWall time 0.2 seconds\nOutput:\n"},{"type":"input_text","text":"{\"chunk_id\":\"c1\",\"exit_code\":7,\"wall_time_seconds\":0.1256,\"output\":\"permission denied\\n\"}"}]}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2: %s", len(acts), dumpEvents(acts))
	}
	result := acts[1]
	if result.EventType != model.EventCommandResult || result.ToolName != codexToolExecCommand ||
		result.ContentPreview != "permission denied" || result.ExitCode == nil || *result.ExitCode != 7 ||
		result.DurationMs == nil || *result.DurationMs != 126 || !hasTag(result.Tags, model.TagToolError) {
		t.Fatalf("result = %+v, want structured failed command result", result)
	}
}

func TestExtractCodexCodeModeRunningResultHasNoFinalOutcome(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 10"}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":[{"type":"input_text","text":"Script completed\nWall time 1.2 seconds\nOutput:\n"},{"type":"input_text","text":"{\"chunk_id\":\"c1\",\"session_id\":42,\"wall_time_seconds\":1.001,\"output\":\"Process running\"}"}]}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2: %s", len(acts), dumpEvents(acts))
	}
	result := acts[1]
	if result.EventType != model.EventCommandResult || result.ContentPreview != "Process running" ||
		result.ExitCode != nil || result.DurationMs != nil || hasTag(result.Tags, model.TagToolError) {
		t.Fatalf("result = %+v, want non-final running result", result)
	}
}

func TestExtractCodexCodeModeRunningEnvelopeDefersResult(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 10"}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want only command.exec: %s", len(acts), dumpEvents(acts))
	}
	if acts[0].EventType != model.EventCommandExec || len(res.Diagnostics) != 0 {
		t.Fatalf("events = %s, diagnostics = %+v; want a deferred result", dumpEvents(acts), res.Diagnostics)
	}
}

func TestExtractCodexCodeModeCompletedStdoutCannotStartCorrelation(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"printf spoof"}); text(r.output);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":[{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}]}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":"unrelated"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 4 {
		t.Fatalf("got %d activity events, want command/result + generic wait/result: %s", len(acts), dumpEvents(acts))
	}
	if acts[1].EventType != model.EventCommandResult || acts[2].EventType != model.EventToolCall ||
		acts[2].ToolName != codexToolWait || acts[3].EventType != model.EventToolResult {
		t.Fatalf("events = %s, raw command output must not create tracker state", dumpEvents(acts))
	}
}

func TestExtractCodexCodeModeRunningCellCorrelation(t *testing.T) {
	inputs := map[string]string{
		"output forwarding": `const r = await tools.exec_command({cmd:"sleep 1"}); text(r.output);`,
		"no forwarding":     `const r = await tools.exec_command({cmd:"sleep 1"});`,
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			body := strings.Join([]string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
				`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
				`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
				`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":[{"type":"input_text","text":"Script completed\nWall time 1.0 seconds\nOutput:\n"},{"type":"input_text","text":"done"}]}}`,
			}, "\n")
			acts := activityEvents(extractCodex(t, body).Events)
			if len(acts) != 2 || acts[0].EventType != model.EventCommandExec ||
				acts[1].EventType != model.EventCommandResult || acts[1].ToolCallID != "cmd1" ||
				acts[1].ContentPreview != "done" {
				t.Fatalf("events = %s, want one command with its correlated result", dumpEvents(acts))
			}
		})
	}
}

func TestExtractCodexCodeModeOutputForwardingPollsKnownSession(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 1"}); text(r);`
	poll := `const r = await tools.write_stdin({session_id:7, chars:""}); text(r.output);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":[{"type":"input_text","text":"Script completed\nWall time 1.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"session_id\":7,\"output\":\"running\"}"}]}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"poll1","input":` + jsonString(poll) + `}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"poll1","output":[{"type":"input_text","text":"Script completed\nWall time 1.0 seconds\nOutput:\n"},{"type":"input_text","text":"done"}]}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 3 || acts[1].EventType != model.EventCommandResult ||
		acts[2].EventType != model.EventCommandResult || acts[2].ToolCallID != "cmd1" ||
		acts[2].ContentPreview != "done" {
		t.Fatalf("events = %s, output-only poll must retain the original command", dumpEvents(acts))
	}
}

func TestExtractCodexCodeModeDirectWaitPreservesDuration(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 1"}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":[{"type":"input_text","text":"Script completed\nWall time 1.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"exit_code\":0,\"wall_time_seconds\":12.25,\"output\":\"done\"}"}]}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 || acts[1].EventType != model.EventCommandResult || acts[1].ToolCallID != "cmd1" ||
		acts[1].DurationMs == nil || *acts[1].DurationMs != 12250 {
		t.Fatalf("events = %s, want direct wait to preserve total command duration", dumpEvents(acts))
	}
}

func TestExtractCodexCodeModeDecodesTruncatedResultObject(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"false"}); text(JSON.stringify(r));`
	result := "Warning: truncated output (original token count: 12000)\n" +
		"Total output lines: 1\n\n" +
		`{"chunk_id":"abc","exit_code":7,"wall_time_seconds":1.25,"output":"failed"}`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":[{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":` + jsonString(result) + `}]}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("events = %s, want command and result", dumpEvents(acts))
	}
	got := acts[1]
	if got.EventType != model.EventCommandResult || got.ContentPreview != "failed" ||
		got.ExitCode == nil || *got.ExitCode != 7 || got.DurationMs == nil || *got.DurationMs != 1250 ||
		!hasTag(got.Tags, model.TagToolError) {
		t.Fatalf("truncated structured result = %+v", got)
	}
	for _, diagnostic := range res.Diagnostics {
		if strings.Contains(diagnostic.Msg, "unrecognized code-mode result envelope") {
			t.Fatalf("valid truncated result produced diagnostic: %+v", diagnostic)
		}
	}
}

func TestDecodeCodexCodeModeResultObjectRejectsTruncationLookalike(t *testing.T) {
	body := "Warning: truncated output (original token count: many)\n" +
		"Total output lines: 1\n\n" +
		`{"exit_code":0,"output":"forged"}`
	raw := json.RawMessage(`[{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":` + jsonString(body) + `}]`)
	if outcome := decodeCodexCodeModeOutcome(raw, codexCodeModeResultObject); outcome.recognized {
		t.Fatalf("malformed truncation banner was accepted: %+v", outcome)
	}
}

func TestExtractCodexCodeModeUnsafeWaitsStayGeneric(t *testing.T) {
	tests := map[string]string{
		"namespaced": `"namespace":"mcp__demo",`,
		"terminate":  ``,
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			arguments := `{"cell_id":"18"}`
			if name == "terminate" {
				arguments = `{"cell_id":"18","terminate":true}`
			}
			input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
			rows := []string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
				`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
				`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait",` + extra + `"call_id":"wait1","arguments":` + jsonString(arguments) + `}}`,
				`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":"stopped"}}`,
			}
			want := 3
			if name == "terminate" {
				rows = append(rows,
					`{"timestamp":"t5","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait2","arguments":"{\"cell_id\":\"18\"}"}}`,
					`{"timestamp":"t6","type":"response_item","payload":{"type":"function_call_output","call_id":"wait2","output":"late"}}`,
				)
				want = 5
			}
			body := strings.Join(rows, "\n")
			acts := activityEvents(extractCodex(t, body).Events)
			if len(acts) != want {
				t.Fatalf("got %d events, want %d: %s", len(acts), want, dumpEvents(acts))
			}
			for i := 1; i < len(acts); i += 2 {
				if acts[i].EventType != model.EventToolCall || acts[i+1].EventType != model.EventToolResult {
					t.Fatalf("events = %s, want generic wait call/result pairs", dumpEvents(acts))
				}
			}
		})
	}
}

func TestExtractCodexCodeModeCallIDReuseDropsOldOwner(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"same","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"custom_tool_call","name":"other","call_id":"same","input":"{}"}}`,
		`{"timestamp":"t5","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"new owner"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 3 || acts[1].EventType != model.EventToolCall || acts[2].EventType != model.EventToolResult {
		t.Fatalf("events = %s, reused call id must not retain the old command owner", dumpEvents(acts))
	}
}

func TestExtractCodexCodeModeLocalShellTakesReusedWaitID(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"same","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"local_shell_call","call_id":"same","action":{"type":"exec","command":["echo","new"]}}}`,
		`{"timestamp":"t5","type":"response_item","payload":{"type":"function_call_output","call_id":"same","output":"new"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 3 || acts[1].EventType != model.EventCommandExec || acts[1].ToolCallID != "same" ||
		acts[2].EventType != model.EventCommandResult || acts[2].ToolCallID != "same" {
		t.Fatalf("events = %s, local shell must replace the pending wait owner", dumpEvents(acts))
	}
}

func TestExtractCodexCodeModeGenericFunctionTakesReusedShellID(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"local_shell_call","call_id":"same","action":{"type":"exec","command":["echo","old"]}}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"function_call","name":"other","call_id":"same","arguments":"{}"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call_output","call_id":"same","output":"new owner"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 3 || acts[1].EventType != model.EventToolCall || acts[2].EventType != model.EventToolResult {
		t.Fatalf("events = %s, generic function must replace the shell owner", dumpEvents(acts))
	}
}

func TestCodexCodeModeSessionOwnershipTransfers(t *testing.T) {
	result := func(sessionID int) json.RawMessage {
		return json.RawMessage(`[{"type":"input_text","text":"Script completed\nWall time 1.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"session_id\":` + strconv.Itoa(sessionID) + `,\"output\":\"running\"}"}]`)
	}
	poll := func(sessionID int) string {
		return `const r = await tools.write_stdin({session_id:` + strconv.Itoa(sessionID) + `, chars:""}); text(r);`
	}
	var tracker codexCodeModeTracker
	tracker.noteExec("cmd1", codexCodeModeResultObject)
	ref, ok := tracker.takeCustomCall("cmd1")
	if !ok {
		t.Fatal("initial command owner missing")
	}
	tracker.trackOutcome(ref, result(1))
	if !tracker.noteWriteStdinPoll("poll1", poll(1)) {
		t.Fatal("first session was not tracked")
	}
	ref, ok = tracker.takeCustomCall("poll1")
	if !ok {
		t.Fatal("first poll owner missing")
	}
	tracker.trackOutcome(ref, result(2))
	if tracker.noteWriteStdinPoll("stale", poll(1)) {
		t.Fatal("old session retained ownership after transition")
	}
	if !tracker.noteWriteStdinPoll("current", poll(2)) {
		t.Fatal("new session did not receive ownership")
	}
}

func TestCodexCodeModeForgetCallDropsOwnedState(t *testing.T) {
	owned := codexCodeModeResultRef{commandCallID: "owner"}
	tracker := codexCodeModeTracker{
		customCalls: map[string]codexCodeModeResultRef{"poll": owned},
		waitCalls:   map[string]codexCodeModeResultRef{"wait": owned},
		cells:       map[string]codexCodeModeResultRef{"cell": owned},
		sessions:    map[string]codexCodeModeResultRef{"session": owned},
	}
	tracker.forgetCall("owner")
	if len(tracker.customCalls) != 0 || len(tracker.waitCalls) != 0 ||
		len(tracker.cells) != 0 || len(tracker.sessions) != 0 {
		t.Fatalf("owned state survived call reuse: %+v", tracker)
	}
}

func TestExtractCodexCodeModeLongRunningCommandCorrelation(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
	poll := `const r = await tools.write_stdin({session_id:25546, chars:"", yield_time_ms:30000}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":"Script running with cell ID 18\nWall time 1.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t5","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait2","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t6","type":"response_item","payload":{"type":"function_call_output","call_id":"wait2","output":[{"type":"input_text","text":"Script completed\nWall time 30.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"session_id\":25546,\"wall_time_seconds\":30,\"output\":\"still running\"}"}]}}`,
		`{"timestamp":"t7","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"poll1","input":` + jsonString(poll) + `}}`,
		`{"timestamp":"t8","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"poll1","output":"Script running with cell ID 19\nWall time 30.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t9","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait3","arguments":"{\"cell_id\":\"19\"}"}}`,
		`{"timestamp":"t10","type":"response_item","payload":{"type":"function_call_output","call_id":"wait3","output":[{"type":"input_text","text":"Script completed\nWall time 12.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"exit_code\":7,\"wall_time_seconds\":12,\"output\":\"failed\"}"}]}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 3 {
		t.Fatalf("got %d activity events, want command + two result updates: %s", len(acts), dumpEvents(acts))
	}
	call, running, final := acts[0], acts[1], acts[2]
	if call.EventType != model.EventCommandExec || call.ToolCallID != "cmd1" || call.Command != "sleep 60" {
		t.Fatalf("call = %+v, want original command.exec", call)
	}
	if running.EventType != model.EventCommandResult || running.ToolCallID != "cmd1" ||
		running.ContentPreview != "still running" || running.ExitCode != nil || running.DurationMs != nil {
		t.Fatalf("running result = %+v, want correlated non-terminal update", running)
	}
	if final.EventType != model.EventCommandResult || final.ToolCallID != "cmd1" ||
		final.ContentPreview != "failed" || final.ExitCode == nil || *final.ExitCode != 7 ||
		final.DurationMs != nil || !hasTag(final.Tags, model.TagToolError) {
		t.Fatalf("final result = %+v, want correlated terminal failure", final)
	}
	if len(res.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", res.Diagnostics)
	}
}

func TestExtractCodexCodeModeUnrelatedWaitAndInputStayGeneric(t *testing.T) {
	poll := `const r = await tools.write_stdin({session_id:25546, chars:"x"}); text(r);`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"unknown\"}"}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"poll1","input":` + jsonString(poll) + `}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 || acts[0].EventType != model.EventToolCall || acts[0].ToolName != codexToolWait ||
		acts[1].EventType != model.EventToolCall || acts[1].ToolName != codexToolCodeModeExec {
		t.Fatalf("events = %s, want unrelated wait and interactive input as generic calls", dumpEvents(acts))
	}
}

func TestExtractCodexCodeModeFailedEnvelopeIsToolError(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"missing"}); text(JSON.stringify(r));`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":[{"type":"input_text","text":"Script failed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":"Script error:\nprocess could not start"}]}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2: %s", len(acts), dumpEvents(acts))
	}
	result := acts[1]
	if result.EventType != model.EventCommandResult || result.ContentPreview != "Script error: process could not start" ||
		result.ExitCode != nil || result.DurationMs != nil || !hasTag(result.Tags, model.TagToolError) || len(res.Diagnostics) != 0 {
		t.Fatalf("result = %+v, diagnostics = %+v; want a structured tool error without an exit code", result, res.Diagnostics)
	}
}

func TestExtractCodexCodeModeStdoutJSONIsNotAnOutcome(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"cat result.json"}); text(r.output);`
	stdout := `{"exit_code":9,"wall_time_seconds":2,"output":"not metadata"}`
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"e1","output":[{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":` + jsonString(stdout) + `}]}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2: %s", len(acts), dumpEvents(acts))
	}
	result := acts[1]
	if result.EventType != model.EventCommandResult || result.ContentPreview != stdout ||
		result.ExitCode != nil || result.DurationMs != nil || hasTag(result.Tags, model.TagToolError) {
		t.Fatalf("result = %+v, stdout JSON must remain content only", result)
	}
}

func TestCodexCodeModeCommandAcceptsDocumentedPragmaAndQuotedKeys(t *testing.T) {
	input := "// @exec: {\"yield_time_ms\": 10000}\n" +
		`const result = await tools.exec_command({"cmd":"git status","workdir":"/repo",}); text(JSON.stringify(result));`
	command, ok := codexCodeModeExecCommand(input)
	if !ok || command != "git status" {
		t.Fatalf("command = %q, ok = %v, want git status/true", command, ok)
	}
}

func TestCodexCodeModeCommandAcceptsASIStatementBoundary(t *testing.T) {
	input := "const result = await tools.exec_command({cmd:\"git status\"})\ntext(result.output)"
	command, ok := codexCodeModeExecCommand(input)
	if !ok || command != "git status" {
		t.Fatalf("command = %q, ok = %v, want git status/true", command, ok)
	}
}

func TestCodexCodeModeCommandAcceptsStaticOutputFallback(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"git status"}); text(r.output || "(no output)");`
	command, ok := codexCodeModeExecCommand(input)
	if !ok || command != "git status" {
		t.Fatalf("command = %q, ok = %v, want git status/true", command, ok)
	}
}

func TestExtractCodexAmbiguousCodeModeExecStaysGeneric(t *testing.T) {
	tests := map[string]string{
		"dynamic command":         `const r = await tools.exec_command({cmd: command}); text(r.output);`,
		"template command":        "const r = await tools.exec_command({cmd: `git ${verb}`}); text(r.output);",
		"duplicate command":       `const r = await tools.exec_command({cmd:"git status", cmd:other}); text(r.output);`,
		"spread may override":     `const r = await tools.exec_command({cmd:"git status", ...options}); text(r.output);`,
		"leading computation":     `const command = "git status"; const r = await tools.exec_command({cmd:command}); text(r.output);`,
		"second nested tool":      `const r = await tools.exec_command({cmd:"git status"}); await tools.write_stdin({session_id:r.session_id});`,
		"parallel nested tools":   `const rs = await Promise.all([tools.exec_command({cmd:"git status"}), tools.exec_command({cmd:"git diff"})]); text(rs);`,
		"additional statement":    `const r = await tools.exec_command({cmd:"git status"}); text(r.output); exit();`,
		"dynamic output fallback": `const r = await tools.exec_command({cmd:"git status"}); text(r.output || fallback);`,
		"missing statement break": `const r = await tools.exec_command({cmd:"git status"}) text(r.output);`,
		"reserved binding":        `const await = await tools.exec_command({cmd:"git status"});`,
		"split text identifier":   `const r = await tools.exec_command({cmd:"git status"}); te xt(r);`,
		"split output identifier": `const r = await tools.exec_command({cmd:"git status"}); text(r.out put);`,
		"shadowed text helper":    `const text = await tools.exec_command({cmd:"git status"}); text(text);`,
		"shadowed JSON helper":    `const JSON = await tools.exec_command({cmd:"git status"}); text(JSON.stringify(JSON));`,
		"empty command":           `const r = await tools.exec_command({cmd:" "}); text(r.output);`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			line := `{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":` + jsonString(input) + `}}`
			acts := activityEvents(extractCodex(t, line).Events)
			if len(acts) != 1 || acts[0].EventType != model.EventToolCall || acts[0].ToolName != codexToolCodeModeExec || acts[0].Command != "" {
				t.Fatalf("events = %s, want one generic exec tool.call", dumpEvents(acts))
			}
		})
	}
}

func TestExtractCodexCodeModeOutputDoesNotCrossCallKinds(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"same","arguments":"{\"cmd\":\"true\"}"}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"same","input":"const r = await tools.exec_command({cmd:\"id\"}); text(r.output);"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"same","input":"await tools.exec_command({cmd: command})"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"rows"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 4 {
		t.Fatalf("got %d activity events, want 4: %s", len(acts), dumpEvents(acts))
	}
	if acts[3].EventType != model.EventToolResult {
		t.Fatalf("custom output = %s, want tool.result after reused custom-call id", acts[3].EventType)
	}
}

func FuzzCodexCodeModeExecCommand(f *testing.F) {
	for _, seed := range []string{
		`const r = await tools.exec_command({cmd:"git status"}); text(r.output);`,
		`const r = await tools.exec_command({cmd:dynamic});`,
		`const rs = await Promise.all([tools.exec_command({cmd:"a"}), tools.exec_command({cmd:"b"})]);`,
		"// @exec: {\"yield_time_ms\": 10}\nconst r = await tools.exec_command({cmd:\"go test ./...\"});",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		command, ok := codexCodeModeExecCommand(input)
		if ok && strings.TrimSpace(command) == "" {
			t.Fatal("accepted an empty command")
		}
	})
}
