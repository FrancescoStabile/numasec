# numasec Manifesto

numasec is the AI agent for cyber security operators.
Not a chat. Not a fork with a green skin. An operator's console.

We hold these six principles, in order of weight.

### 1. Operator first, model second.
The operator owns the engagement. The model is a fast, opinionated colleague — never the
authority. Every consequential action is a proposal the operator can confirm, reject, or
override. We surface what the model is thinking and what it is about to do, in plain text,
on a terminal.

### 2. Public brain.
Every kind prompt, glyph, default tool list and TUI string is in this repository, in plain
files, under MIT. If you cannot read a system prompt before trusting it, it is not yours.
We will be the first AI security tool whose entire reasoning surface is auditable from
the same `git clone`.

### 3. Authorized scope is sacred.
numasec assumes you operate inside an authorized engagement and refuses to invent
permissions you do not have. The boundary guard is not a moral filter — it is an
operator‑defined contract that the agent is obligated to respect. Out‑of‑scope work is
denied, not negotiated.

### 4. Reproducible or it did not happen.
Every engagement is a sequence of events that can be exported to a single `.numasec` file
and replayed step‑by‑step on another machine without touching a real target. Findings
without evidence and replay are notes, not findings.

### 5. Five disciplines, one lineup.
pentest, appsec, osint, security and hacking are equi‑citizens. We will not let the
project drift into "the pentest tool with osint as an afterthought". Each kind has its
own prompt, theme, glyph, placeholders and default disposition. Switching kinds is one
keystroke.

### 6. Refuse magic.
No fragile parsers wrapping every CLI tool, no hand‑coded chain state machines, no
proprietary policies layered over the model provider, no telemetry, no cloud backend,
no auto‑updating taxonomies that drift overnight. Capability lives in primitives the
operator already understands: `bash`, `httprequest`, `browser`, `scanner`, `interact`,
`vault`, `crypto`, `net`, `methodology`, `cve`. The model decides; the operator confirms.

---

If a future change to numasec violates one of these principles, the change is wrong,
not the principle.

— numasec maintainers
