package otel

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// hasTag reports whether tag is present in ev.Tags.
func hasTag(ev model.Event, tag string) bool {
	for _, t := range ev.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// eventNameAttr builds the event.name ATTRIBUTE carrier that Codex and Gemini
// actually use (the LogRecord.event_name proto field is left empty), so these
// tests exercise the same seam the agents hit: wire decode -> attribute lookup
// -> classify.
func eventNameAttr(name string) []byte { return kv(attrEventName, name) }

func TestClaudeAliases(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "claude-code")}

	t.Run("user prompt with bare event attribute", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr("user_prompt"),
			kv(attrPrompt, "inspect the release"),
			kv(attrEventTimestamp, "2026-07-13T12:34:56Z"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPromptUser || ev.ContentPreview != "inspect the release" {
			t.Fatalf("prompt event = %+v", ev)
		}
		if ev.Timestamp != "2026-07-13T12:34:56Z" {
			t.Fatalf("timestamp = %q", ev.Timestamp)
		}
		mustValidate(t, ev)
	})

	t.Run("assistant response", func(t *testing.T) {
		rec := recBuilder{eventName: claudeAssistantResponse, attrs: [][]byte{
			kv(attrClaudeResponse, "done"),
			kv(attrModel, "claude-sonnet-5"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventMessageAssistant || ev.Model != "claude-sonnet-5" || ev.ContentPreview != "done" {
			t.Fatalf("assistant event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("failed bash result", func(t *testing.T) {
		rec := recBuilder{eventName: claudeToolResult, attrs: [][]byte{
			kv(attrAliasToolName, "Bash"),
			kv(attrClaudeToolUseID, "tool-1"),
			kv(attrClaudeToolParameters, `{"bash_command":"cat .env"}`),
			kv(attrSuccess, "false"),
			kvAny(attrDurationMs, anyInt(42)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventCommandResult || ev.Command != "cat .env" || ev.ToolCallID != "tool-1" {
			t.Fatalf("command result = %+v", ev)
		}
		if ev.DurationMs == nil || *ev.DurationMs != 42 || !hasTag(ev, model.TagToolError) {
			t.Fatalf("command metadata = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("file write result", func(t *testing.T) {
		rec := recBuilder{eventName: claudeToolResult, attrs: [][]byte{
			kv(attrAliasToolName, "Edit"),
			kv(attrClaudeToolInput, `{"file_path":"/repo/main.go"}`),
			kv(attrSuccess, "true"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventFileWrite || ev.FilePath != "/repo/main.go" {
			t.Fatalf("file event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("web fetch result", func(t *testing.T) {
		rec := recBuilder{eventName: claudeToolResult, attrs: [][]byte{
			kv(attrAliasToolName, "WebFetch"),
			kv(attrClaudeToolInput, `{"url":"https://example.test/path"}`),
			kv(attrSuccess, "true"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventNetworkIndicator || ev.URL != "https://example.test/path" {
			t.Fatalf("network event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("tool decision", func(t *testing.T) {
		rec := recBuilder{eventName: claudeToolDecision, attrs: [][]byte{
			kv(attrAliasToolName, "Bash"),
			kv(attrClaudeToolUseID, "tool-2"),
			kv(attrDecision, "reject"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPermissionDenied || ev.ApprovalDecision != model.DecisionDenied || ev.ToolCallID != "tool-2" {
			t.Fatalf("decision event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("subagent result", func(t *testing.T) {
		rec := recBuilder{eventName: claudeToolResult, attrs: [][]byte{
			kv(attrAliasToolName, "Agent"),
			kv(attrClaudeToolParameters, `{"subagent_type":"security-reviewer"}`),
			kv(attrSuccess, "true"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult || ev.SubAgent != "security-reviewer" || ev.Actor != model.ActorTool {
			t.Fatalf("subagent result = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("permission mode", func(t *testing.T) {
		rec := recBuilder{eventName: claudePermissionModeChanged, attrs: [][]byte{
			kv(attrClaudeToMode, "bypassPermissions"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventConfigAgent || !hasTag(ev, model.TagPermissionModeElevated) {
			t.Fatalf("permission mode event = %+v", ev)
		}
		mustValidate(t, ev)
	})
}

// TestCodexAliases proves each security-relevant codex.* record now classifies
// (Mapped=true) onto the right event_type with its key fields, with the
// event.name carried as an attribute (not the proto field).
func TestCodexAliases(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "codex-cli")}

	t.Run("conversation_starts", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexConversationStarts),
			kv(attrProviderName, "openai"),
			kv(attrSessionID, "sess-c1"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventSessionStart {
			t.Errorf("event_type = %q, want session.start", ev.EventType)
		}
		if ev.Actor != model.ActorSystem {
			t.Errorf("actor = %q, want system", ev.Actor)
		}
		if ev.ModelProvider != "openai" {
			t.Errorf("model_provider = %q, want openai", ev.ModelProvider)
		}
		mustValidate(t, ev)
	})

	t.Run("user_prompt", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexUserPrompt),
			kv(attrPrompt, "delete the prod database"),
			kvAny("prompt_length", anyInt(24)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPromptUser {
			t.Errorf("event_type = %q, want prompt.user", ev.EventType)
		}
		if ev.Actor != model.ActorUser {
			t.Errorf("actor = %q, want user", ev.Actor)
		}
		if ev.ContentPreview != "delete the prod database" {
			t.Errorf("content_preview = %q", ev.ContentPreview)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_decision_denied", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexToolDecision),
			kv(attrAliasToolName, "apply_patch"),
			kv(attrCallID, "call-7"),
			kv(attrDecision, "denied"),
			kv("source", "user"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPermissionDenied {
			t.Errorf("event_type = %q, want permission.denied", ev.EventType)
		}
		if ev.ApprovalDecision != model.DecisionDenied {
			t.Errorf("approval_decision = %q", ev.ApprovalDecision)
		}
		if ev.ToolName != "apply_patch" {
			t.Errorf("tool_name = %q", ev.ToolName)
		}
		if ev.ToolCallID != "call-7" {
			t.Errorf("tool_call_id = %q, want call-7", ev.ToolCallID)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_decision_approved", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexToolDecision),
			kv(attrAliasToolName, "shell"),
			kv(attrDecision, "approved"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPermissionApproved {
			t.Errorf("event_type = %q, want permission.approved", ev.EventType)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_result_shell_failure", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexToolResult),
			kv(attrAliasToolName, "exec_command"),
			kv(attrCallID, "call-9"),
			kv(attrArguments, `{"cmd":"cat .env"}`),
			kvAny(attrDurationMs, anyInt(1200)),
			kv(attrSuccess, "false"), // Codex success is a STRING
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventCommandResult {
			t.Errorf("event_type = %q, want command.result", ev.EventType)
		}
		if ev.Command != "cat .env" {
			t.Errorf("command = %q, want cat .env", ev.Command)
		}
		if ev.DurationMs == nil || *ev.DurationMs != 1200 {
			t.Errorf("duration_ms = %v, want 1200", ev.DurationMs)
		}
		if ev.ToolCallID != "call-9" {
			t.Errorf("tool_call_id = %q", ev.ToolCallID)
		}
		if !hasTag(ev, model.TagToolError) {
			t.Errorf("expected tool_error tag from success=false string, got %v", ev.Tags)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_result_mcp", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexToolResult),
			kv(attrAliasToolName, "search"),
			kv(attrMCPServer, "ctx7"),
			kv(attrSuccess, "true"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result", ev.EventType)
		}
		if ev.MCPServer != "ctx7" || ev.MCPTool != "search" {
			t.Errorf("mcp split = %q/%q, want ctx7/search", ev.MCPServer, ev.MCPTool)
		}
		if hasTag(ev, model.TagToolError) {
			t.Errorf("success=true should not flag tool_error: %v", ev.Tags)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_result_retains_output", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(codexToolResult),
			kv(attrAliasToolName, "shell"),
			kv(attrOutput, "total 0\ndrwxr-xr-x  2 root root"),
			kv(attrSuccess, "true"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.ContentPreview != "total 0 drwxr-xr-x 2 root root" {
			t.Errorf("content_preview = %q, want the output snippet retained", ev.ContentPreview)
		}
		mustValidate(t, ev)
	})
}

// TestGeminiAliases proves each gemini_cli.* record classifies onto the right
// event_type. Gemini also carries event.name as an attribute.
func TestGeminiAliases(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "gemini-cli")}

	t.Run("config starts session", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiConfig),
			kv(attrModel, "gemini-2.5-pro"),
			kv(attrApprovalMode, "yolo"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventSessionStart || ev.Actor != model.ActorSystem || ev.Model != "gemini-2.5-pro" || !hasTag(ev, model.TagPermissionModeElevated) {
			t.Fatalf("config event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("user_prompt", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiUserPrompt),
			kv(attrPrompt, "list all secrets"),
			kv("prompt_id", "p-1"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPromptUser {
			t.Errorf("event_type = %q, want prompt.user", ev.EventType)
		}
		if ev.ContentPreview != "list all secrets" {
			t.Errorf("content_preview = %q", ev.ContentPreview)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_call_shell_with_decision", func(t *testing.T) {
		// Gemini carries the shell payload inside function_args (a JSON object
		// encoded in a string AnyValue), NOT a top-level command attribute. No
		// command attr is set here, so this only passes if function_args is read.
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiToolCall),
			kv(attrFunctionName, "run_shell_command"),
			kv(attrFunctionArgs, `{"command":"rm -rf /","description":"wipe"}`),
			kv(attrDecision, "auto_accept"),
			kvAny(attrDurationMs, anyInt(25)),
			kvAny(attrSuccess, anyBool(true)), // Gemini success is a BOOL
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventCommandResult {
			t.Errorf("event_type = %q, want command.result", ev.EventType)
		}
		if ev.Command != "rm -rf /" {
			t.Errorf("command = %q, want it recovered from function_args", ev.Command)
		}
		if ev.Decision != model.DecisionAllowed {
			t.Errorf("decision = %q, want allowed (auto_accept)", ev.Decision)
		}
		if ev.DurationMs == nil || *ev.DurationMs != 25 || ev.Actor != model.ActorTool {
			t.Errorf("result metadata = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_call_failure_bool", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiToolCall),
			kv(attrFunctionName, "grep"),
			kvAny(attrSuccess, anyBool(false)), // BOOL false -> tool_error
			kv(attrErrorType, "ENOENT"),
			kv(attrDecision, "reject"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result", ev.EventType)
		}
		if !hasTag(ev, model.TagToolError) {
			t.Errorf("expected tool_error from success=false bool / error_type, got %v", ev.Tags)
		}
		if ev.Decision != model.DecisionDenied {
			t.Errorf("decision = %q, want denied (reject)", ev.Decision)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_call_mcp", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiToolCall),
			kv(attrFunctionName, "fetch_url"),
			kv(attrMCPServerName, "fetch"),
			kvAny(attrSuccess, anyBool(true)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result", ev.EventType)
		}
		if ev.MCPServer != "fetch" || ev.MCPTool != "fetch_url" {
			t.Errorf("mcp split = %q/%q, want fetch/fetch_url", ev.MCPServer, ev.MCPTool)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_call_file_write", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiToolCall),
			kv(attrFunctionName, "write_file"),
			kv(attrFunctionArgs, `{"file_path":"/tmp/agent.txt","content":"x"}`),
			kv(attrDecision, "accept"),
			kvAny(attrSuccess, anyBool(true)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventFileWrite || ev.FilePath != "/tmp/agent.txt" || ev.Decision != model.DecisionAllowed {
			t.Fatalf("file tool event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_call_file_write_without_logged_args", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiToolCall),
			kv(attrFunctionName, "write_file"),
			kvAny(attrSuccess, anyBool(true)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventFileWrite || ev.FilePath != "" {
			t.Fatalf("file tool without arguments = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("api response", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiAPIResponse),
			kv(attrModel, "gemini-2.5-pro"),
			kv(attrResponseText, "finished the review"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventMessageAssistant || ev.ContentPreview != "finished the review" || ev.Model != "gemini-2.5-pro" {
			t.Fatalf("api response = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("subagent lifecycle", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			want model.EventType
		}{
			{geminiAgentStart, model.EventSessionStart},
			{geminiAgentFinish, model.EventSessionEnd},
		} {
			rec := recBuilder{attrs: [][]byte{
				eventNameAttr(tc.name),
				kv(attrAgentName, "codebase-investigator"),
				kv(attrAgentID, "agent-1"),
			}}.build()
			ev := mustMap(t, resource, rec)
			if ev.EventType != tc.want || ev.SubAgent != "codebase-investigator" || ev.Actor != model.ActorSystem {
				t.Fatalf("%s event = %+v", tc.name, ev)
			}
			mustValidate(t, ev)
		}
	})

	t.Run("conversation end", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{eventNameAttr(geminiConversationFinished)}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventSessionEnd || ev.Actor != model.ActorSystem {
			t.Fatalf("conversation end = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("approval mode switch", func(t *testing.T) {
		for _, name := range []string{geminiApprovalModeSwitch, geminiApprovalModeSwitchLegacy} {
			rec := recBuilder{attrs: [][]byte{
				eventNameAttr(name),
				kv(attrClaudeToMode, "auto_edit"),
			}}.build()
			ev := mustMap(t, resource, rec)
			if ev.EventType != model.EventConfigAgent || !hasTag(ev, model.TagPermissionModeElevated) {
				t.Fatalf("approval mode event %q = %+v", name, ev)
			}
			mustValidate(t, ev)
		}
	})

	t.Run("file_operation_skips", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(geminiFileOperation),
			kv(attrAliasToolName, "write_file"),
			kv("operation", "create"),
			kv(attrGenAIToolName, "write_file"),
			kv(attrFilePath, "/tmp/coincidental.txt"),
		}}.build()
		if res := mapOne(t, resource, rec); res.Mapped || !res.Ignored {
			t.Fatalf("supplemental file operation result = %+v", res)
		}
	})
}

func TestGeminiQwenFileOperationDoesNotDuplicateToolCall(t *testing.T) {
	tests := []struct {
		name         string
		service      string
		toolEvent    string
		fileEvent    string
		functionName string
		functionArgs string
		wantAgent    string
	}{
		{"gemini", "gemini-cli", geminiToolCall, geminiFileOperation, "write_file", `{"file_path":"/tmp/gemini.txt"}`, model.AgentGeminiCLI},
		{"qwen", "qwen-code", qwenToolCall, qwenFileOperation, "WriteFile", `{"file_path":"/tmp/qwen.txt"}`, model.AgentQwenCode},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ids := []string{"ev-tool", "ev-file"}
			toolCall := recBuilder{attrs: [][]byte{
				eventNameAttr(tc.toolEvent),
				kv(attrFunctionName, tc.functionName),
				kv(attrFunctionArgs, tc.functionArgs),
				kvAny(attrSuccess, anyBool(true)),
			}}.build()
			fileOperation := recBuilder{attrs: [][]byte{
				eventNameAttr(tc.fileEvent),
				kv(attrAliasToolName, tc.functionName),
				kv("operation", "create"),
			}}.build()

			results, err := MapRecords(
				exportRequest([][]byte{kv(attrServiceName, tc.service)}, toolCall, fileOperation),
				func(i int) string { return ids[i] },
			)
			if err != nil {
				t.Fatalf("MapRecords: %v", err)
			}
			if len(results) != 2 || !results[0].Mapped || results[1].Mapped || !results[1].Ignored {
				t.Fatalf("map results = %+v", results)
			}
			ev := results[0].Event
			if ev.EventType != model.EventFileWrite || ev.SourceAgent != tc.wantAgent || ev.FilePath == "" {
				t.Fatalf("canonical file event = %+v", ev)
			}
			mustValidate(t, ev)
		})
	}
}

func TestQwenAliases(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "qwen-code")}

	t.Run("config starts session", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(qwenConfig),
			kv(attrModel, "qwen3-coder-plus"),
			kv(attrApprovalMode, "auto_edit"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.SourceAgent != model.AgentQwenCode || ev.EventType != model.EventSessionStart || ev.Model != "qwen3-coder-plus" || !hasTag(ev, model.TagPermissionModeElevated) {
			t.Fatalf("Qwen config event = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("prompt and assistant response", func(t *testing.T) {
		prompt := recBuilder{attrs: [][]byte{
			eventNameAttr(qwenUserPrompt),
			kv(attrPrompt, "review the workspace"),
		}}.build()
		ev := mustMap(t, resource, prompt)
		if ev.EventType != model.EventPromptUser || ev.ContentPreview != "review the workspace" {
			t.Fatalf("Qwen prompt = %+v", ev)
		}
		mustValidate(t, ev)

		response := recBuilder{attrs: [][]byte{
			eventNameAttr(qwenAPIResponse),
			kv(attrModel, "qwen3-coder-plus"),
			kv(attrResponseText, "review complete"),
		}}.build()
		ev = mustMap(t, resource, response)
		if ev.EventType != model.EventMessageAssistant || ev.ContentPreview != "review complete" || ev.Model != "qwen3-coder-plus" {
			t.Fatalf("Qwen response = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("shell tool result", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(qwenToolCall),
			kv(attrFunctionName, "Bash"),
			kv(attrFunctionArgs, `{"command":"cat .env"}`),
			kv(attrToolCallID, "qwen-call-1"),
			kv(attrDecision, "auto_accept"),
			kvAny(attrSuccess, anyBool(true)),
			kvAny(attrDurationMs, anyInt(18)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventCommandResult || ev.Command != "cat .env" || ev.ToolCallID != "qwen-call-1" || ev.Decision != model.DecisionAllowed {
			t.Fatalf("Qwen shell result = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("camel-case file tool", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(qwenToolCall),
			kv(attrFunctionName, "WriteFile"),
			kv(attrFunctionArgs, `{"file_path":"/tmp/qwen.txt","content":"x"}`),
			kvAny(attrSuccess, anyBool(false)),
			kv(attrError, "permission denied"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventFileWrite || ev.FilePath != "/tmp/qwen.txt" || !hasTag(ev, model.TagToolError) {
			t.Fatalf("Qwen file result = %+v", ev)
		}
		mustValidate(t, ev)
	})

	t.Run("subagent lifecycle and conversation end", func(t *testing.T) {
		for _, tc := range []struct {
			status string
			want   model.EventType
		}{
			{"started", model.EventSessionStart},
			{"failed", model.EventSessionEnd},
		} {
			rec := recBuilder{attrs: [][]byte{
				eventNameAttr(qwenSubagentExecution),
				kv(attrSubagentName, "reviewer"),
				kv(attrStatus, tc.status),
			}}.build()
			ev := mustMap(t, resource, rec)
			if ev.EventType != tc.want || ev.SubAgent != "reviewer" || ev.Actor != model.ActorSystem {
				t.Fatalf("Qwen subagent %s = %+v", tc.status, ev)
			}
			mustValidate(t, ev)
		}

		rec := recBuilder{attrs: [][]byte{eventNameAttr(qwenConversationFinished)}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventSessionEnd {
			t.Fatalf("Qwen conversation end = %+v", ev)
		}
		mustValidate(t, ev)
	})
}

// TestOpenCodeAliases proves each of the five DEVtheOPS-plugin OpenCode events
// classifies (Mapped=true) onto the right event_type with its key fields. The
// event.name is the bare name carried as an attribute, the same wire->classify
// seam the live plugin hits.
func TestOpenCodeAliases(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "opencode")}

	t.Run("service_name_resolves", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{eventNameAttr(opencodeSessionCreated)}}.build()
		res := mapOne(t, resource, rec)
		if res.SourceAgent != model.AgentOpenCode {
			t.Errorf("source_agent = %q, want opencode", res.SourceAgent)
		}
	})

	t.Run("user_prompt_no_content_preview", func(t *testing.T) {
		// OpenCode carries prompt_length, NOT the prompt text — so content_preview
		// must stay empty (no text to redact), and model is recovered.
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeUserPrompt),
			kvAny("prompt_length", anyInt(42)),
			kv(attrModel, "anthropic/claude"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPromptUser {
			t.Errorf("event_type = %q, want prompt.user", ev.EventType)
		}
		if ev.Actor != model.ActorUser {
			t.Errorf("actor = %q, want user", ev.Actor)
		}
		if ev.ContentPreview != "" {
			t.Errorf("content_preview = %q, want empty (prompt_length only)", ev.ContentPreview)
		}
		if ev.Model != "anthropic/claude" {
			t.Errorf("model = %q", ev.Model)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_result_success", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeToolResult),
			kv(attrAliasToolName, "read"),
			kvAny(attrDurationMs, anyInt(15)),
			kvAny(attrSuccess, anyBool(true)),
			kvAny("tool_result_size_bytes", anyInt(2048)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result", ev.EventType)
		}
		if ev.ToolName != "read" {
			t.Errorf("tool_name = %q", ev.ToolName)
		}
		// duration_ms is dropped: the contract gates it onto command.result, which
		// OpenCode tool_result deliberately does not become.
		if ev.DurationMs != nil {
			t.Errorf("duration_ms = %v, want nil on tool.result", ev.DurationMs)
		}
		if hasTag(ev, model.TagToolError) {
			t.Errorf("success=true should not flag tool_error: %v", ev.Tags)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_result_shell_is_NOT_command_result", func(t *testing.T) {
		// A bash tool_result must still map to tool.result, never command.result:
		// OpenCode gives no exec signal beyond tool_name, so synthesizing a
		// command.result would be a false positive. A missed command.result is the
		// accepted false negative here.
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeToolResult),
			kv(attrAliasToolName, "bash"),
			kvAny(attrSuccess, anyBool(true)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result (no command.result synthesis)", ev.EventType)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_result_error", func(t *testing.T) {
		// OpenCode success is a real BOOL (the divergence from Codex's string), and
		// a failure also carries an error string at severity ERROR.
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeToolResult),
			kv(attrAliasToolName, "edit"),
			kvAny(attrSuccess, anyBool(false)),
			kv("error", "permission denied"),
		}, severityText: "ERROR"}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result", ev.EventType)
		}
		if !hasTag(ev, model.TagToolError) {
			t.Errorf("expected tool_error from success=false bool, got %v", ev.Tags)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_decision_accept", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeToolDecision),
			kv(attrAliasToolName, "bash"),
			kv(attrCallID, "call-oc1"),
			kv("tool_type", "bash"),
			kv(attrDecision, "accept"),
			kv("source", "allow"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPermissionApproved {
			t.Errorf("event_type = %q, want permission.approved", ev.EventType)
		}
		if ev.ApprovalDecision != model.DecisionAllowed {
			t.Errorf("approval_decision = %q, want allowed", ev.ApprovalDecision)
		}
		if ev.ToolName != "bash" {
			t.Errorf("tool_name = %q", ev.ToolName)
		}
		if ev.ToolCallID != "call-oc1" {
			t.Errorf("tool_call_id = %q", ev.ToolCallID)
		}
		mustValidate(t, ev)
	})

	t.Run("tool_decision_reject", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeToolDecision),
			kv(attrAliasToolName, "write"),
			kv(attrDecision, "reject"),
			kv("source", "reject"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventPermissionDenied {
			t.Errorf("event_type = %q, want permission.denied", ev.EventType)
		}
		if ev.ApprovalDecision != model.DecisionDenied {
			t.Errorf("approval_decision = %q, want denied", ev.ApprovalDecision)
		}
		mustValidate(t, ev)
	})

	t.Run("session_created", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeSessionCreated),
			kv(attrSessionID, "sess-oc1"),
			kvAny("is_subagent", anyBool(false)),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventSessionStart {
			t.Errorf("event_type = %q, want session.start", ev.EventType)
		}
		if ev.Actor != model.ActorSystem {
			t.Errorf("actor = %q, want system", ev.Actor)
		}
		if ev.SessionID != "sess-oc1" {
			t.Errorf("session_id = %q", ev.SessionID)
		}
		mustValidate(t, ev)
	})

	t.Run("session_deleted", func(t *testing.T) {
		rec := recBuilder{attrs: [][]byte{
			eventNameAttr(opencodeSessionDeleted),
			kv(attrSessionID, "sess-oc1"),
		}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != model.EventSessionEnd {
			t.Errorf("event_type = %q, want session.end", ev.EventType)
		}
		if ev.Actor != model.ActorSystem {
			t.Errorf("actor = %q, want system", ev.Actor)
		}
		mustValidate(t, ev)
	})
}

// TestOpenCodeExactNameOnly proves OpenCode's bare names are matched exactly:
// the documented out-of-scope events and near-misses skip rather than misclassify.
func TestOpenCodeExactNameOnly(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "opencode")}
	for _, name := range []string{
		"api_request",     // documented out-of-scope noise: must skip
		"api_error",       // documented out-of-scope noise: must skip
		"subtask_invoked", // documented out-of-scope: must skip
		"session.error",   // noisier than session.idle: must skip
		"session.idle",    // end-of-turn signal, not a terminal session end
		"user_prompts",    // near-miss (trailing s): must NOT match
	} {
		rec := recBuilder{attrs: [][]byte{eventNameAttr(name)}}.build()
		res := mapOne(t, resource, rec)
		if res.Mapped {
			t.Errorf("event.name %q should not alias (exact-match only), got %q", name, res.Event.EventType)
		}
	}
}

// TestOpenCodeBareNamesGatedToOpenCode proves the high-precision fix: OpenCode's
// BARE event.name aliases (user_prompt/tool_result/tool_decision/session.created/
// session.deleted) fire ONLY when the record's service.name resolved to OpenCode. A
// same-named record from any other emitter (codex-cli, gemini-cli, or an
// unrecognized service) must skip rather than be misclassified — a bare-name
// collision is exactly the false positive auspex forbids.
func TestOpenCodeBareNamesGatedToOpenCode(t *testing.T) {
	bareNames := []string{
		opencodeUserPrompt,
		opencodeToolResult,
		opencodeToolDecision,
		opencodeSessionCreated,
		opencodeSessionDeleted,
	}
	for _, svc := range []string{"codex-cli", "gemini-cli", "some-other"} {
		resource := [][]byte{kv(attrServiceName, svc)}
		for _, name := range bareNames {
			rec := recBuilder{attrs: [][]byte{eventNameAttr(name)}}.build()
			res := mapOne(t, resource, rec)
			if res.Mapped {
				t.Errorf("bare event.name %q from service %q must NOT alias (gated to OpenCode), got %q",
					name, svc, res.Event.EventType)
			}
		}
	}
}

// TestOpenCodeBareNamesFireForOpenCode is the positive counterpart: with
// service.name resolving to OpenCode, all five bare names still map correctly,
// confirming the gate did not break the intended path.
func TestOpenCodeBareNamesFireForOpenCode(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "opencode")}
	want := map[string]model.EventType{
		opencodeUserPrompt:     model.EventPromptUser,
		opencodeToolResult:     model.EventToolResult,
		opencodeToolDecision:   model.EventPermissionRequested,
		opencodeSessionCreated: model.EventSessionStart,
		opencodeSessionDeleted: model.EventSessionEnd,
	}
	for name, eventType := range want {
		rec := recBuilder{attrs: [][]byte{eventNameAttr(name)}}.build()
		ev := mustMap(t, resource, rec)
		if ev.EventType != eventType {
			t.Errorf("bare event.name %q for OpenCode = %q, want %q", name, ev.EventType, eventType)
		}
	}
}

// TestAliasExactNameOnly proves the high-precision bias: a near-miss event.name
// (a codex.* / gemini_cli.* noise event, or a substring) is NOT aliased and
// falls through to skip, so a documented false negative beats any false positive.
func TestAliasExactNameOnly(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "codex-cli")}
	for _, name := range []string{
		"codex.api_request",        // documented noise: must skip
		"codex.sse_event",          // documented noise: must skip
		"codex.tool_decisions",     // near-miss (trailing s): must NOT match
		"prefix.codex.user_prompt", // substring: must NOT match
	} {
		rec := recBuilder{attrs: [][]byte{eventNameAttr(name)}}.build()
		res := mapOne(t, resource, rec)
		if res.Mapped {
			t.Errorf("event.name %q should not alias (exact-match only), got %q", name, res.Event.EventType)
		}
	}
}

// TestAliasProtoEventNameStillWorks confirms that when an exporter DOES set the
// LogRecord.event_name proto field (rather than the attribute), aliasing still
// fires — eventName() prefers the proto field.
func TestAliasProtoEventNameField(t *testing.T) {
	resource := [][]byte{kv(attrServiceName, "codex-cli")}
	rec := recBuilder{
		eventName: codexUserPrompt, // proto field carrier
		attrs:     [][]byte{kv(attrPrompt, "hello")},
	}.build()
	ev := mustMap(t, resource, rec)
	if ev.EventType != model.EventPromptUser {
		t.Errorf("event_type = %q, want prompt.user via proto event_name", ev.EventType)
	}
}

func mustMap(t *testing.T, resourceAttrs [][]byte, rec []byte) model.Event {
	t.Helper()
	res := mapOne(t, resourceAttrs, rec)
	if !res.Mapped {
		t.Fatalf("expected record to map, got skip (agent %s)", res.SourceAgent)
	}
	return res.Event
}

func mustValidate(t *testing.T, ev model.Event) {
	t.Helper()
	if err := ev.Validate(); err != nil {
		t.Errorf("event failed model contract Validate: %v", err)
	}
}
