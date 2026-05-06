# `.numasec` Replay Format — v1

A `.numasec` file is a self-contained, line-delimited JSON stream describing one numasec engagement (or a single run within one). It is designed so anyone can `numasec replay <file>.numasec` and walk through the original conversation step by step, without ever re-executing a tool against a live target.

This is the OSS-friendly format: plain text, one JSON object per line, gzip-friendly, diff-able, easy to host on a gist or attach to a forum post. Binary evidence is **not** embedded — that is an explicit v1 trade-off.

---

## File shape

```
{ "type": "header",  ... }       ← line 1, exactly one
{ "type": "event",   ... }       ← lines 2..N, one per replay event
{ "type": "trailer", ... }       ← last line, exactly one
```

- Encoding: **UTF-8**, line ending `\n`, no BOM.
- One JSON object per line (no pretty-printing inside lines).
- File extension: `.numasec`. MIME hint: `application/x-numasec+jsonl`.
- Empty/blank lines are illegal.

A consumer that fails to parse any line MUST stop and report the line number.

---

## Header

```json
{
  "type": "header",
  "format": "numasec/1",
  "id": "<session id or operation id>",
  "scope": "session" | "operation",
  "kind": "security" | "pentest" | "appsec" | "osint" | "hacking",
  "title": "<human title>",
  "created_at": "2026-04-17T08:34:12Z",
  "exported_at": "2026-04-18T11:02:00Z",
  "numasec_version": "1.2.0",
  "model": { "provider": "anthropic", "id": "claude-opus-4.7" },
  "redacted": false
}
```

Required: `type`, `format`, `id`, `scope`, `kind`, `created_at`, `exported_at`, `numasec_version`. Extra fields are allowed and MUST be preserved by writers/readers that pass through.

---

## Events

Each event line carries `type: "event"` plus an `event` discriminator describing the original message/tool action:

- `message` — assistant or user message text part.
- `tool_call` — tool was invoked, with name + arguments (arguments redacted if `--redact`).
- `tool_result` — final tool output (truncated to a configurable byte cap; default 64 KiB per result, with `truncated: true` flag if cut).
- `op_event` — Operation-level event (scope change, observation added, plan node update). Optional, only present for `scope: "operation"`.

Common envelope:

```json
{
  "type": "event",
  "event": "tool_call",
  "ts": "2026-04-17T08:34:18.221Z",
  "seq": 14,
  "session_id": "ses_…",
  "message_id": "msg_…",
  "data": { ... event-specific ... }
}
```

`seq` is monotonically increasing per file, starts at 1 (the first event line). Replay walks events in `seq` order.

### `event: "message"`

```json
{
  "data": {
    "role": "user" | "assistant",
    "text": "…",
    "redacted_spans": [{ "start": 142, "end": 160 }]
  }
}
```

### `event: "tool_call"`

```json
{
  "data": {
    "tool": "bash",
    "call_id": "tc_…",
    "input": { "command": "nmap -sV 10.10.11.42" },
    "input_redacted": false
  }
}
```

### `event: "tool_result"`

```json
{
  "data": {
    "call_id": "tc_…",
    "status": "completed" | "error",
    "duration_ms": 312,
    "stdout": "…",
    "stderr": "…",
    "exit_code": 0,
    "truncated": false
  }
}
```

For tools other than `bash`, fields collapse into `output` (a JSON value) instead of stdout/stderr/exit_code.

### `event: "op_event"`

```json
{
  "data": {
    "kind": "observation_added" | "plan_node_updated" | "scope_proposed" | ...,
    "payload": { ... opaque, schema-forward-compatible ... }
  }
}
```

---

## Trailer

```json
{
  "type": "trailer",
  "events": 137,
  "duration_ms": 4821000,
  "sha256_body": "<hex sha256 of all event lines concatenated, with newlines>",
  "signed": false,
  "signature": null
}
```

`sha256_body` is computed over `header_line + "\n" + event_lines.join("\n") + "\n"` excluding the trailer line itself. This anchors the file: any tampering changes the hash.

If a signing tool (`minisign` or `cosign`) is available and the operator passes `--sign`, the signature material goes into `signature`:

```json
"signature": {
  "scheme": "minisign",
  "public_key_id": "RWQ...",
  "value": "<base64>"
}
```

The signature signs `sha256_body`.

---

## Redaction

With `--redact`:

- `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization` headers in tool inputs/outputs replaced with `[redacted:header:<name>]`.
- JWT-shaped tokens (`eyJ...`) replaced with `[redacted:jwt]`.
- Common credential params (`password`, `api_key`, `token`, `secret`) in JSON or query-string inputs replaced with `[redacted:secret:<name>]`.
- IPv4/IPv6 addresses in private RFC1918 ranges optionally replaced with `[redacted:ip]` if `--redact=ips` is passed.

Header `redacted: true` is set on the file when any redaction was applied.

---

## Replay semantics

`numasec replay <file>` MUST:

1. Verify the header is `format: "numasec/1"`. Refuse otherwise.
2. Verify `sha256_body` matches the recomputed digest. Warn loudly if not (do not refuse — a hand-edited file may still be useful).
3. If `signature` is present and a verifier is available, verify it. Output the verification status.
4. Render events in `seq` order in a frozen TUI session view. No tool re-execution. No network. No shell.
5. Support `--step` (pause on each event, advance with key) and `--speed Nx` (replay at N times original timing).

A replayer MUST NOT silently invoke real tools, even if the file references them.

---

## Versioning

`format: "numasec/1"`. Future versions bump the integer. Readers MUST refuse files whose major version they do not understand.

Additive fields are allowed within v1 and MUST be ignored by older readers without erroring.

---

## What's intentionally not in v1

- Binary evidence bundles. (Out of scope per founder decision; can ship later as a sibling `.numasec.bundle` tar.zst file referencing the same `id` + `sha256_body`.)
- Encrypted at-rest format. (Use OS-level encryption or sign+seal externally.)
- Multi-session bundles. (One file = one engagement scope.)
- Live diff between two files. (External tool concern.)
