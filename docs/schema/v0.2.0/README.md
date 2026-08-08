# auspex record schemas v0.2.0

This directory contains JSON Schema Draft 2020-12 contracts for auspex's emitted
NDJSON records.

- `record-stream.schema.json` accepts any record line from the main record
  stream (`event`, `finding`, `enforcement`, `indicator`, or terminal
  `scan_summary`) or the separate diagnostic stream (`diagnostic`).
- The per-record schemas are the contracts to use when a downstream receiver
  routes on `record_type`.

Configure your validator to resolve the relative `$ref` values in
`record-stream.schema.json` against this directory.
Enable `date-time` format assertions when validating. The time-field patterns
enforce lexical and UTC shape; format assertions reject impossible dates.

Every emitted line carries an `endpoint` object with `hostname`, `os`, `arch`,
`username`, and `uid`. Set `AUSPEX_DEVICE_ID` to add a stable opaque
`endpoint.device_id` for fleet joins.

A line also carries `ruleset_digest` whenever the run resolved a rule catalog:
a `sha256:` fold of every loaded rule file's raw bytes, keyed by rule id. It is
byte-sensitive on purpose. `--rules-dir` replaces a built-in rule that shares
its stable id, so a stub carrying a built-in's id and declared `version` runs in
place of the shipped detection; hashing declared identity would return the
unchanged value for exactly that substitution. Sorting by id rather than path
keeps two endpoints running the same catalog comparable. When operator rules
replace built-in ids, the run also emits a `warn` diagnostic naming them.

The digest attests **which rules were loaded**, nothing more. It does not show
that auspex was invoked, that the hook is still wired, or that a decision was
enforced — anyone able to drop in a `--rules-dir` can equally unwire the hook.
The key is absent when no catalog was resolved for that record: an event-only
run never compiles an engine, and a diagnostic may be written before rules are
loaded. Absence is "not asked", never "nothing found".

These schemas are amended in place with additive optional fields, which
[CONTRIBUTING.md](../../../CONTRIBUTING.md) does not treat as breaking. Because
every record schema sets `additionalProperties: false`, a receiver validating
against a *pinned* copy of a v0.2.0 schema will reject records carrying fields
added after that copy was taken. Re-fetch this directory rather than pinning a
snapshot, or relax `additionalProperties` on your side.

The schemas describe the emitted wire shape. They do not change runtime
behavior. They keep auspex's flat [event model](../../event-model.md): rules
evaluate the same field names that records emit.

Action event types are alternatives, not layers. A recognized shell, file, or
network tool action uses `command.exec`, `file.*`, or `network.indicator`
instead of an additional `tool.call`; `tool.call` is the fallback. When a
source provides a separate outcome, shell outcomes use `command.result` and
other outcomes use `tool.result`. A structured multi-file edit may expand to
one file event per affected path.

When findings are selected, a matched, enforce-capable pre-action hook also
emits an `enforcement` record with auspex's computed `deny` or `no_override`
decision. It joins to rule matches and the proposed action through
`finding_ids` and `action_event_ids`. The record is written before the control
response and does not prove response delivery or host behavior.

Evidence refs always carry `artifact_type`. File-backed refs also carry
`local_path`; live hook and OTLP refs may omit it because there is no local file
to reopen.

`event.project_path`, `event.file_path`, and finding `observed_file_path` use `/`
separators on every operating system so one rule works across platforms.
`evidence.local_path` remains host-native because it is an endpoint reopen path.

Context fields such as `model`, `model_provider`, and `entrypoint` are
source-specific and omitted when the source does not record them.

On findings, `timestamp` is the matched event's activity time (the completing
event for a sequence) and may be absent when that event has no valid timestamp.
`detected_at` is when auspex created the finding.
