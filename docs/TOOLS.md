# numasec — Tool Reference (v1.1.5 Launch Identity)

This is a quick reference of the primitive tools shipped in the numasec core. Every
tool is LLM-friendly: minimal schema, no fragile output parsers, no hidden state
beyond per-session buffers. The agent reads raw tool output and reasons over it.

## File & code

- **read / write / edit / multiedit / apply_patch** — filesystem primitives
- **grep / glob / codesearch** — search primitives

## Network

- **http_request** — HTTP calls with scope boundary guard
- **webfetch** — fetch + markdown conversion for reading web pages
- **websearch** — web search (provider-backed)
- **net** *(new)* — raw TCP/UDP send + banner grab (one-shot; no interactive shells)

## Browser (Playwright)

- **browser** — one tool, many actions:
  - `navigate`, `click`, `fill`, `screenshot`, `evaluate`, `get_cookies`
  - *(new in 1.1.5)* `dom_snapshot`, `storage_snapshot`, `console_log`, `network_tab`, `dom_diff`

## Crypto & encoding

- **crypto** *(new)* — `hash`, `hmac`, `encode`, `decode`, `jwt_decode`, `xor`
  - Algorithms: sha1/sha256/sha384/sha512/md5 + common HMAC variants
  - Codecs: base64 / hex / url / rot13

## Identity & secrets

- **secrets** *(new)* — plain-JSON credential vault at `$XDG_CONFIG_HOME/numasec/secrets.json`
  - `set`, `get`, `list`, `remove`
  - NOTE: stored in plain JSON in v1. Encrypted vault planned for a later milestone.
- **auth_as** *(new)* — auth profiles at `$XDG_CONFIG_HOME/numasec/auth-profiles.json`
  - `set` a named profile (`basic`, `bearer`, `cookie`, `form`) with credentials payload
  - Referenced by name from `http_request` / `browser` to replay authenticated sessions

## Out-of-band

- **interact** *(new)* — OOB callback generator
  - `generate`: returns a callback URL (interactsh if `interactsh-client` on PATH, else `webhook.site` fallback)
  - `poll`: returns captured hits (DNS/HTTP) since last poll
  - `close`: tear down the session
  - Required for SSRF, blind XSS, DNS-based OOB verification

## Orchestration

- **task / todowrite / skill / question / plan_exit** — session + flow primitives
- **bash** — arbitrary shell (scope-guarded for known network commands)
- **observe_surface** — kind-specific surface enumeration helper

## Notes for agent authors

- Prefer primitives over shelling out to ad-hoc tools; when the primitive doesn't
  cover a case, fall back to `bash`.
- `secrets` values are never emitted in transcript plain-text in production modes —
  the tool returns them only when explicitly asked via `get`, and the operator
  should treat the transcript accordingly.
- `net` and `interact` require operator permission per invocation via `ctx.ask`.
