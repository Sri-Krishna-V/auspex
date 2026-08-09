# Event model

auspex maps supported artifacts, hooks, and OTLP logs into the same closed
event vocabulary. Rules and outputs therefore use stable action names even
when agents record the same activity differently.

The model preserves source identity and evidence. It does not try to reproduce
every vendor field or infer action types from prose.

## Classification

A tool request becomes the most specific event that its structured name and
arguments support:

| Observed action | Normalized type | Principal field |
| --- | --- | --- |
| Shell or process request | `command.exec` | `command` |
| File access or change | `file.read`, `file.write`, `file.delete` | `file_path` |
| Known web or network request | `network.indicator` | `url` when available |
| Other or unknown tool request | `tool.call` | `tool_name` |

These types are alternatives, not layers. A recognized shell request produces
`command.exec`, not an additional `tool.call`. `tool.call` preserves visibility
when auspex cannot safely assign a more specific type. `event_type` carries the
action category; there is no parallel category field.

Classification is deliberately narrow:

- Artifact and hook parsers use agent-specific tool names and structured
  argument keys verified from that source.
- OTLP uses supported semantic-convention attributes and explicit operation
  fields. A path-bearing record remains `tool.call` when its direction is
  ambiguous.
- Unknown tools are not promoted by loose name or content matching.
- Command output, assistant prose, and free-form previews are not searched to
  invent file or network actions.
- A supported wrapper may be specialized when it contains exactly one
  statically recoverable action. auspex never evaluates embedded code; dynamic
  or compound wrappers remain `tool.call`.

`confidence` describes how directly the source supports the mapping. The
source provenance, including its location when available, remains in
`evidence`.

## Requests and results

A result is a separate observation, not a second request. When the source
provides an identifier, `tool_call_id` joins:

- `command.exec` to `command.result`
- `tool.call` to `tool.result`
- specialized file or network requests to later tool or permission records

Some agents persist only one side, and long-running commands may emit more than
one result update. An absent `exit_code` means the source did not provide one;
it does not mean success.

## MCP

MCP is a facet of a tool action, not a separate event category. A qualified
tool such as `mcp__github__create_issue` remains `tool.call` with
`mcp_server: github` and `mcp_tool: create_issue`. The canonical MCP fetch tool
becomes `network.indicator` by exact server and tool identity; a structured
target is promoted to `url` only when it is valid HTTP(S). It retains the MCP
fields.

`config.mcp` describes an observed MCP configuration. It does not represent a
tool invocation.

## Examples

The examples below show only the source fragment and the relevant normalized
fields. Emitted records also contain the versioned envelope, source and session
context, confidence, endpoint identity, and evidence reference.

A Claude Code tool block:

```json
{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"git status"}}
```

becomes:

```json
{"event_type":"command.exec","tool_name":"Bash","tool_call_id":"toolu_1","command":"git status"}
```

A Codex MCP call whose server and tool identify the canonical fetch service:

```json
{"type":"function_call","name":"mcp__fetch__fetch","call_id":"call_1","arguments":"{\"url\":\"https://example.com/a\"}"}
```

becomes:

```json
{"event_type":"network.indicator","tool_name":"mcp__fetch__fetch","tool_call_id":"call_1","mcp_server":"fetch","mcp_tool":"fetch","url":"https://example.com/a"}
```

## Opacity

Command events carry `opacity_score`, a count of the reasons the command's
effect could not be read from its text, and `opacity_reasons`, the markers that
were counted. The score is always the length of the array, so an aggregate can
use either alone. Five markers exist, each worth 1:

| Marker | Meaning |
| --- | --- |
| `detached` | `nohup`, `setsid`, or `disown` outlives the observed session |
| `dynamic_argument` | an argument or redirect target resolves only at runtime |
| `encoded_payload` | a decoder (`base64`, `xxd`, `uudecode`, `base32`, `openssl enc`, `certutil -decode`) produces bytes never present in the command |
| `inline_interpreter` | an interpreter takes its program from the argv (`bash -c`, `perl -e`, `pwsh -EncodedCommand`, `cmd /c`) |
| `piped_to_interpreter` | an interpreter executes a program delivered on its standard input |

Reasons are reported in that fixed order, so two endpoints observing the same
command emit an identical array.

POSIX shell, PowerShell, and `cmd.exe` commands are all analyzed — the markers
are derived from the same parse that backs `shell_commands`, not from a
dialect-specific pass.

**A score of 0 is a claim; an absent score is not.** `0` means auspex parsed the
command and saw everything it does. Absence means auspex did not look or could
not read it — the event carries no command, or the command was unparseable, over
the analyzer's size limit, or in a dialect it cannot project. A command auspex
could not read is left **unscored**, never scored 0, because reporting 0 there
would assert a completeness auspex cannot support. Consumers must treat the two
as different states.

The score measures how much of the action is hidden from a static reader, not
how dangerous it is. `bash -c "echo hi"` scores 1. The marker set is a fixed
list of known wrapping techniques, not a proof of transparency: a 0 means none
of these five were seen, not that no concealment exists. Nothing in the shipped
catalog matches on it; the field is exposed to CEL as `event.opacity_score` and
`event.opacity_reasons` so operators can write their own thresholds.

## Contracts

The event vocabulary and allowed field combinations are closed and validated
before detection or emission. Context fields such as `model`, `project_path`,
and `sub_agent` are present only when the source records them. Semantic paths
use `/` separators on every operating system; evidence paths remain native so
the source can be reopened on the endpoint.

See [Writing rules](rules.md) for the CEL field and event-type contracts,
[Agent coverage](agent-coverage.md) for source-specific support, and the
[record schemas](schema/v0.2.0/) for the emitted wire format.
