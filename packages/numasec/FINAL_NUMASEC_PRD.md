# Numasec PRD v2.0

Date: 2026-05-02

Status: replacement PRD.

Product definition: Numasec is the Codex CLI for cyber security. It is a terminal-native, multi-provider, operator-sovereign cyber agent harness that makes frontier LLMs effective by immersing them in the right security workspace: Kali-grade execution, structured memory, live knowledge, semantic tool adapters, evidence, replay, oracles and benchmarks.

This PRD replaces the previous Authz-first PRD. Authorization testing remains an important domain capsule, but it is not the product identity.

## Cold Audit Of The Previous PRD

The previous PRD had a strong wedge, but it also contained product glaze.

What was solid:

- The Codex analogy was correct.
- The emphasis on terminal-native operation was correct.
- The idea that models need a cyber-native environment, not just prompts, was correct.
- The insistence on evidence, replay, deterministic oracles and benchmark gates was correct.
- Web/API authorization was a valid high-signal starting problem.
- The warning against "200 shallow tools" was correct.

What was glaze:

- It claimed a cyber workbench kernel while specifying mostly an authz scanner workflow.
- It over-indexed on one domain and then projected future multi-domain strength without proving the substrate.
- It treated one vertical benchmark as enough evidence for a broad cyber product thesis.
- It implied near-zero false positives before defining cross-domain proof standards.
- It made the exact three-tool design feel more certain than it was.
- It mentioned GPT-Cyber as an optimization without proving how model profiles change outcomes.
- It estimated implementation timing too confidently for a net-new kernel.

10/10 confidence claims:

- Numasec cannot modify the base LLM; the product leverage is the wrapper.
- The wrapper must provide environment, tools, state, memory, retrieval, permissions, verification and reporting.
- A cyber agent without evidence and replay will hallucinate polished findings.
- A cyber agent with a giant flat tool list will waste context and choose poorly.
- A multi-domain cyber product must be benchmarked domain by domain.
- Numasec will not be "effective in every field" by declaration. It becomes effective only where its domain capsule has tool grounding, memory, oracles and passing evals.

Not 10/10 confidence:

- Which domain should be first.
- How autonomous real-world pentesting can safely become in release 1.2.0 and later.
- Whether any named cyber model will outperform the best general reasoning model in every workflow.
- Whether one schema can represent all cyber domains cleanly.
- Whether users want more autonomous execution or more operator-assisted acceleration.

The new PRD keeps the hard parts and removes the narrow product identity.

## Core Thesis

Codex is not strong because it is a chat UI for code. Codex is strong because it wraps a model in a developer operating system:

- local workspace access;
- file search and editing;
- shell execution;
- tests, typechecks and build logs;
- git state and diffs;
- approvals and sandboxing;
- memory and project instructions;
- skills, MCP, subagents and automation;
- tight inspect, act, verify loops.

Numasec must do the same for cyber security.

Cyber equivalents:

- repository -> target workspace;
- source files -> traffic, hosts, services, repos, artifacts, packets, logs, identities, cloud state and OSINT sources;
- tests -> exploit replay, sanitizer output, static analysis proof, dependency reachability, flag checks, source provenance and regression tests;
- git diff -> request diff, state diff, attack graph diff, finding diff;
- build logs -> tool transcripts, scanner outputs, browser traces, command outputs;
- commit -> signed proof bundle;
- worktree -> isolated lab or scoped operation;
- AGENTS.md -> operation rules, scope, methodology and team memory.

The product is not "an AI pentester". The product is a cyber operator harness around the best available model.

## Product Stance

Numasec is operator-native, not enterprise-dashboard-first.

Numasec should feel like a security professional gained a tireless terminal partner that already understands the target workspace, installed tools, current vulnerabilities, previous attempts, evidence rules and report format.

Numasec should be:

- terminal-native;
- local-first;
- multi-provider;
- model-aware but model-independent;
- Kali-compatible;
- evidence-first;
- replay-oriented;
- benchmarked;
- extensible through domain capsules, skills, plugins and MCP;
- explicit about autonomy, scope, risk and side effects.

Numasec should not be:

- a wrapper around 200 commands with no semantic memory;
- an authz-only product;
- a pentest-only product;
- a compliance dashboard;
- a generic chat assistant with security prompts;
- a tool that promotes unverified claims;
- dependent on one vendor model;
- blocked by target-ownership proof gates in core UX.

The operator owns authorization, legality and engagement scope. Numasec owns observability, risk labeling, budgets, evidence, replay, and honest reporting.

## Product Promise

Numasec helps an operator do cyber work across domains:

- penetration testing;
- AppSec: SAST, DAST, SCA, secrets, IaC and remediation;
- OSINT and passive reconnaissance;
- hacking labs and CTFs;
- cloud, container and Kubernetes posture;
- binary, reverse engineering and forensics triage;
- vulnerability research and 0-day lab work as a later maturity stage.

The promise is not equal depth on day one.

The promise is that every domain uses the same kernel:

```text
observe -> plan -> execute -> parse -> remember -> verify -> replay -> report -> learn
```

Every domain capsule must define:

- what it observes;
- what tools it can use;
- what memory it writes;
- what knowledge it retrieves;
- what counts as proof;
- how findings are replayed;
- how it is benchmarked.

No domain is allowed to call itself effective until it passes its benchmark.

## Competitive Principles

Numasec should absorb the best ideas from heterogeneous competitors while avoiding their traps.

### Codex And Claude Code

Principle to copy:

- agentic loop;
- local workspace;
- direct terminal action;
- approvals;
- persistent instructions;
- memory;
- subagents;
- skills;
- MCP;
- hooks;
- evaluation and verification loops.

Cyber translation:

- target workspace instead of repo only;
- cyber tools instead of build tools only;
- proof oracles instead of tests only;
- operation ledger instead of chat history only;
- domain capsules instead of code language support.

### XBOW

Principle to copy:

- prove exploitation;
- reduce false positives;
- adapt based on target behavior;
- chain multiple steps;
- produce reproducible detail;
- expose governance, safety, scope and auditability.

Numasec difference:

- operator-local CLI first;
- transparent raw evidence;
- extensible open workbench rather than only a hosted autonomous platform.

### CAI

Principle to copy:

- modular cyber agents;
- multi-model support;
- tool integration;
- tracing;
- guardrails;
- human-in-the-loop control;
- agentic patterns and handoffs.

Numasec difference:

- productized TUI and persistent operation workspace, not only a framework;
- stronger proof and replay contract;
- fewer always-visible tools, more on-demand semantic adapters.

### HexStrike

Principle to copy:

- Kali-like breadth;
- MCP tool orchestration;
- coverage of pentest, bug bounty, CTF, binary and forensics workflows.

Trap to avoid:

- exposing hundreds of tools as flat agent choices;
- treating tool count as product depth.

Numasec should be able to use every installed tool, but it should not stuff every tool into the model context.

### PentestGPT And Related Research Agents

Principle to copy:

- explicit reasoning, generation and parsing loops;
- session persistence;
- command execution;
- output interpretation;
- iterative attack planning.

Numasec difference:

- multi-domain beyond pentest;
- structured operation memory;
- benchmark gates;
- evidence and replay as first-class product objects.

### Aardvark / Codex Security

Principle to copy:

- repo-wide threat modeling;
- commit/change-aware scanning;
- exploitability validation in isolation;
- patch proposal;
- human review;
- high-recall benchmark discipline.

Numasec difference:

- not only AppSec;
- local and multi-provider;
- combines code, live targets, traffic, artifacts and OSINT in one operation.

## Product Architecture

Numasec v2 is built around a cyber kernel plus domain capsules.

The kernel must stay stable while capsules evolve.

### Kernel Capabilities

These are product responsibilities, not a demand to create nine separate packages or network services.

Implement them through the existing Effect/runtime architecture where possible. Split implementation only when the codebase proves that a boundary is real.

#### 1. Operation Ledger

Append-only event stream for the operation.

Records:

- user goals;
- scope changes;
- tool actions;
- approvals;
- command transcripts;
- browser actions;
- HTTP requests;
- scanner outputs;
- imported artifacts;
- hypotheses;
- failed attempts;
- findings;
- report exports.

The ledger is the source of truth for what happened.

There is no separate human-first operation notebook in the product architecture. If `numasec.md` exists, it is an agent-facing compact context pack generated from ledger, graph, memory and open hypotheses. It exists only to help the agent reason inside context limits. It is not canonical state and should be removable once the context packer is good enough.

#### 2. Cyber Workspace Graph

Queryable graph state for cyber entities.

This is the hardest architectural choice in the PRD. Do not implement it as "the agent manually maintains a knowledge graph". That will overload the agent, produce inconsistent state and waste tool calls.

Also do not implement it as blind automatic truth. Parsers can be wrong, scanners can be noisy, and LLM extraction can hallucinate.

The graph is a derived fact index with provenance, not an autonomous source of truth.

Graph population rule:

```text
ledger event -> deterministic parser/extractor -> candidate fact -> provenance link -> graph projection
```

Allowed graph writers:

- deterministic tool parsers: nmap, nuclei, semgrep, trivy, ffuf, HAR, browser network, HTTP, git/repo scanners;
- first-party semantic tools: `http`, `browser`, `terminal`, `analyze`, `knowledge`, `evidence`;
- oracle engine: promotes verified facts and findings;
- operator action: explicit correction, merge, dismiss or promote;
- LLM extractor: candidate facts only, never confirmed facts.

Forbidden graph writers:

- raw assistant prose;
- unparsed generic tool output without an attached evidence artifact;
- LLM-only "I think this exists" claims as confirmed graph facts;
- report generation side effects.

Every graph fact must carry:

- source event ID;
- evidence ID when available;
- writer kind: parser|tool|oracle|operator|llm_candidate;
- confidence;
- status: candidate|observed|verified|rejected|stale;
- timestamps;
- optional expiry/freshness.

Status semantics:

- `candidate`: proposed by LLM or weak parser; useful for planning, not reporting.
- `observed`: extracted deterministically from evidence or tool output.
- `verified`: confirmed by oracle, replay, test, independent corroboration or explicit operator promotion.
- `rejected`: tested and found false.
- `stale`: previously true or observed, but freshness expired or target changed.

The agent consumes graph digests, not the whole graph. The context packer must select a small, task-relevant graph slice: active target, recent observations, open hypotheses, failed attempts, credentials by reference, and proof gaps.

If a domain cannot define reliable extractors and proof promotion rules, that domain should not write rich graph facts yet. It should store evidence and ledger events until parsers exist.

Core entity types:

- operation;
- target;
- domain;
- IP;
- host;
- service;
- port;
- URL;
- route;
- request;
- response;
- identity;
- credential reference;
- repository;
- file;
- package;
- dependency;
- CVE;
- CWE;
- weakness;
- exploit reference;
- cloud resource;
- container image;
- Kubernetes object;
- OSINT entity;
- source;
- artifact;
- hypothesis;
- finding;
- proof.

The graph must be thin and extensible. Do not build a universal ontology before real capsule data requires it. Start with facts that tools can extract reliably.

Storage decision: use SQLite/Drizzle for queryable graph state and operation metadata. Keep replay/audit exports as JSONL files. Do not use markdown as storage.

#### 3. Evidence And Replay Store

Stores immutable proof material.

Evidence types:

- command transcript;
- HTTP exchange;
- browser trace;
- screenshot;
- DOM snapshot;
- network log;
- scanner output;
- static analysis result;
- dependency advisory;
- exploit script;
- test case;
- crash input;
- pcap;
- file hash;
- source citation;
- report bundle.

Every promoted finding must link to evidence. Every high-confidence active finding must include replay steps unless the domain explicitly defines why replay is impossible.

#### 4. Tool Runtime And Adapter Registry

Numasec must be fused with the operator environment.

It should discover:

- installed binaries;
- versions;
- help output;
- supported flags;
- required credentials;
- expected output formats;
- risk class;
- parser availability;
- benchmark coverage.

Tool cards are loaded on demand. The model should search and select tool capabilities instead of seeing hundreds of schemas at once.

Tool classes:

- raw terminal;
- semantic adapters;
- MCP servers;
- browser;
- HTTP;
- code analysis;
- package analysis;
- cloud APIs;
- OSINT sources;
- exploit frameworks;
- lab runners.

Kali Fusion Mode:

- works on Kali, Parrot, BlackArch or any host with tools on PATH;
- inventories tools at startup and through `/doctor`;
- creates adapter cards from known tools and observed help output;
- captures all command transcripts;
- parses outputs into the workspace graph where a parser exists;
- falls back to raw transcript when no parser exists.

Release scope: installed tools only. Do not build or require a Numasec container/lab image for this PRD implementation. Containerized labs can return later as a separate roadmap item.

Using every tool is allowed. Treating every tool as a first-class prompt tool is not.

#### 5. Knowledge And Retrieval Service

The LLM has stale and incomplete security knowledge. Numasec must close that gap.

Knowledge sources:

- local docs and notes;
- operation memory;
- tool manuals;
- CVE/NVD feeds;
- CISA KEV;
- Exploit-DB;
- Metasploit modules;
- vendor advisories;
- GitHub advisories;
- package registries;
- OWASP, CWE, CAPEC and MITRE ATT&CK;
- writeups and CTF references when allowed by mode;
- user-provided methodology docs;
- web search for current information.

Knowledge retrieval must store:

- source URL or local path;
- retrieval time;
- freshness;
- confidence;
- license or redistribution caution when relevant;
- which finding or hypothesis used it.

No unsourced OSINT or vulnerability claim is report-ready.

#### 6. Memory System

Memory must be explicit, queryable and controllable.

Layers:

- session scratchpad: short-lived working notes;
- operation memory: durable facts for one engagement;
- entity graph: structured facts and relationships;
- artifact memory: immutable files and hashes;
- procedural memory: reusable successful trajectories and failed attempts;
- knowledge cache: retrieved external facts with TTL;
- team memory: local conventions, preferred tools and reporting style;
- model context packer: selects what the LLM sees now.

Memory loop:

```text
write -> manage -> retrieve -> act -> verify -> consolidate
```

Rules:

- failed attempts are valuable memory;
- stale knowledge must expire or be marked stale;
- secrets are stored by reference, not copied into summaries;
- memory writes should be attributable to evidence;
- context packing should prefer current scope, active hypotheses and recent failures over broad history.

#### 7. Oracle And Evaluator Engine

An oracle is code or structured procedure that decides whether a claim is supported.

Examples:

- exploit replay succeeds;
- flag value matches expected format;
- unauthorized identity reads protected data;
- SAST claim has source, sink and reachability;
- dependency is present, vulnerable and reachable;
- patch test fails before and passes after;
- crash reproduces under sanitizer;
- OSINT entity is confirmed by independent sources;
- cloud finding maps to actual resource config;
- secret is valid or safely proven without disclosure.

The LLM can propose hypotheses and explain results. It cannot be the final oracle for confirmed findings.

#### 8. Permission And Autonomy Controller

Numasec has two operator-facing execution modes, matching the existing opencode-derived permission ergonomics:

- `permissioned`: default. Target-affecting and risky local actions ask through deny/allow/allow-always.
- `auto`: bounded autonomous execution inside explicit scope and budgets.

Internal planning/read-only behavior can still be implemented with the existing permission system, but it must not appear as a separate product mode unless there is a clear UX reason.

Risk labels:

- `local_read`;
- `local_write`;
- `target_read`;
- `target_mutating`;
- `credentialed`;
- `third_party`;
- `destructive`;
- `stealth_sensitive`;
- `legal_sensitive`.

Controls:

- scope;
- budget;
- rate limits;
- kill switch;
- network boundary;
- time window;
- credential policy;
- output redaction;
- audit export.

These are execution controls, not proof-of-ownership gates.

#### 9. Agent Orchestrator

Numasec is an agent product, not a pile of prompt files.

The orchestrator owns:

- model profile selection;
- plan state;
- subagent delegation;
- tool search;
- context packing;
- critique;
- budget tracking;
- replay generation;
- report assembly.

Model profiles:

- `general`: default reasoning.
- `cyber`: cyber-specialized model if configured.
- `fast`: cheap summarization, parsing and route tagging.
- `code`: code/security review model if distinct.
- `judge`: conservative critic for prioritization and explanation, never final proof.

Agent roles:

- operator: main session owner;
- recon: surface discovery;
- exploit: active testing and PoC construction;
- appsec: source/dependency/config analysis;
- osint: passive collection and provenance;
- forensics: artifacts, timelines and evidence;
- critic: checks weak claims and missing proof;
- reporter: turns proof into deliverables.

Roles are invoked on demand. Do not run a permanent swarm by default.

## User-Facing Tools

The product should expose a small number of deep cyber tools and keep raw terminal access as an escape hatch.

### `workspace`

Manage operation state and graph.

Actions:

- `start`;
- `import`;
- `list`;
- `graph`;
- `digest`;
- `timeline`;
- `export`.

### `terminal`

Controlled command execution.

Actions:

- `run`;
- `which`;
- `help`;
- `inventory`;
- `adapter_status`;
- `replay_command`.

This wraps existing shell capability with risk labels, transcripts, parsers and graph writes.

### `browser`

Interactive web/browser surface.

Actions:

- navigate;
- inspect;
- capture network;
- replay flow;
- screenshot;
- storage/cookie/session management;
- bind identity.

### `http`

Raw and structured HTTP.

Actions:

- request;
- replay;
- diff;
- import HAR;
- capture;
- template;
- fuzz bounded;
- bind identity.

### `knowledge`

Current external and local cyber knowledge.

Actions:

- search;
- fetch;
- lookup CVE;
- lookup exploit;
- lookup package advisory;
- lookup technique;
- cache;
- cite.

### `analyze`

Artifact and code analysis.

Actions:

- repo scan;
- static analysis adapter;
- dependency analysis;
- secrets scan;
- IaC scan;
- container scan;
- binary triage;
- pcap/log triage.

### `runbook`

Domain capsule execution.

Actions:

- list;
- inspect;
- run;
- resume;
- benchmark;
- explain_failures.

### `evidence`

Proof management.

Actions:

- add;
- link;
- replay;
- promote;
- demote;
- report;
- share;
- redact.

### `scope`

Execution boundary.

Actions:

- set;
- show;
- risk;
- budget;
- autonomy;
- stop.

Existing tools can remain internally. The user-facing product should converge toward these semantic surfaces.

## Domain Capsules

A domain capsule is a product module with tools, memory, oracles, runbooks and benchmarks.

### Capsule 1: Pentest Operator

Purpose: active assessment of network, web and API targets.

Inputs:

- target URL/IP/CIDR;
- scope;
- credentials;
- traffic;
- seed wordlists;
- optional source code.

Workspace entities:

- host;
- service;
- port;
- route;
- identity;
- request;
- response;
- vulnerability hypothesis;
- exploit chain;
- proof.

Core tools:

- terminal adapters for nmap, masscan, naabu, httpx, ffuf, gobuster, nuclei, sqlmap, metasploit and custom scripts when installed;
- browser;
- HTTP;
- scanner;
- knowledge;
- evidence.

Oracles:

- exploit replay;
- access control diff;
- service state proof;
- shell or callback proof only in explicitly scoped disposable targets;
- sensitive marker disclosure;
- mutation state diff;
- scanner finding validation.

Deliverable:

- attack surface map;
- verified findings;
- replay commands;
- remediation guidance.

### Capsule 2: AppSec Operator

Purpose: SAST, DAST, SCA, secrets, IaC and secure remediation.

Inputs:

- repository;
- dependency manifests;
- lockfiles;
- running app URL;
- CI logs;
- threat model.

Workspace entities:

- repo;
- file;
- symbol;
- route;
- package;
- dependency;
- CVE;
- CWE;
- source;
- sink;
- config;
- test;
- patch.

Core tools:

- repo search and code intelligence;
- semgrep/codeql adapters when installed;
- trivy, grype, syft, osv-scanner, npm audit/bun audit equivalents where available;
- gitleaks/trufflehog adapters;
- checkov/tfsec/kube-score adapters;
- browser and HTTP for DAST validation;
- test runner and patch workflow.

Oracles:

- source-to-sink reachability;
- vulnerable package is present and reachable;
- secret is real or safely classified without leaking it;
- DAST proof reproduces;
- patch test fails before and passes after;
- CI/test regression passes.

Deliverable:

- verified code findings;
- suspected findings with confidence and missing proof;
- patches or remediation diffs where requested;
- developer-ready tests.

### Capsule 3: OSINT Operator

Purpose: passive intelligence collection with provenance discipline.

Inputs:

- domain;
- organization;
- person/handle;
- IP/netblock;
- brand;
- repository/org.

Workspace entities:

- source;
- domain;
- subdomain;
- IP;
- ASN;
- certificate;
- email;
- handle;
- repository;
- breach reference;
- technology;
- relationship;
- confidence.

Core tools:

- web search;
- DNS/RDAP/whois adapters;
- certificate transparency;
- GitHub search;
- archive sources;
- Shodan/Censys/SecurityTrails if keys exist;
- local notes and source bundles.

Oracles:

- independent source corroboration;
- timestamped source citation;
- entity relationship proof;
- no active target touch in passive mode;
- confidence labeling.

Deliverable:

- sourced entity graph;
- attack surface candidates;
- confidence-rated leads;
- citations and collection log.

### Capsule 4: Hacking And CTF Operator

Purpose: lab hacking, CTF, exploit practice and challenge solving.

Inputs:

- challenge files;
- target lab;
- Docker compose;
- binary;
- pcap;
- web challenge URL;
- flag format.

Workspace entities:

- challenge;
- artifact;
- service;
- exploit script;
- payload;
- flag;
- failed path;
- writeup.

Core tools:

- terminal;
- debugger/reversing tools when installed;
- pwntools;
- python/bun scripts;
- browser and HTTP;
- crypto helpers;
- forensics tools;
- wordlists;
- lab runner.

Oracles:

- flag captured;
- exploit script works from clean reset;
- decoded artifact hash matches;
- service challenge solved;
- writeup steps replay.

Deliverable:

- solved flag;
- replayable exploit;
- concise writeup.

### Capsule 5: Cloud, Container And IaC Operator

Purpose: posture and misconfiguration assessment across infrastructure surfaces.

Inputs:

- cloud credentials;
- Terraform/Kubernetes manifests;
- container images;
- cluster context;
- IaC repo.

Workspace entities:

- account;
- resource;
- policy;
- role;
- image;
- layer;
- package;
- exposed service;
- misconfiguration;
- compliance mapping.

Core tools:

- prowler, steampipe, scout-suite or cloud CLIs when installed;
- trivy/grype/syft;
- checkov/tfsec;
- kubectl/kube-score/kube-bench where available;
- evidence and report.

Oracles:

- resource exists with risky config;
- vulnerable package exists in image;
- policy permits risky action;
- IaC maps to deployed resource when evidence exists;
- remediation changes pass plan/test where possible.

Deliverable:

- posture findings;
- evidence-backed misconfigurations;
- prioritized remediation.

### Capsule 6: Forensics And Incident Triage

Purpose: artifact-first investigation and evidence timeline construction.

Inputs:

- logs;
- disk artifacts;
- pcap;
- memory capture metadata;
- suspicious files;
- endpoint exports.

Workspace entities:

- artifact;
- hash;
- event;
- timestamp;
- process;
- connection;
- indicator;
- hypothesis;
- timeline.

Core tools:

- file/hash tools;
- strings/binwalk/exiftool;
- tshark/zeek/suricata when available;
- log parsers;
- YARA where available;
- knowledge and evidence.

Oracles:

- hash and artifact reproducibility;
- timeline consistency;
- source log citation;
- indicator provenance;
- no unsupported attribution.

Deliverable:

- timeline;
- indicators;
- evidence bundle;
- confidence-rated conclusions.

### Capsule 7: Vulnerability Research Lab

Purpose: advanced vulnerability discovery and exploitability research.

This is not release 1.2.0 general availability unless the operator later approves sandbox/container work. The current release scope is installed tools only.

Required before shipping:

- isolated sandbox;
- harness generation;
- fuzzing adapter;
- sanitizer integration;
- crash dedupe;
- minimization;
- exploitability triage;
- responsible disclosure workflow.

Oracles:

- crash reproduces;
- sanitizer reports same bug class;
- minimized input triggers issue;
- patch or mitigation prevents crash;
- disclosure artifacts are complete.

## Release 1.2.0 Product Cut

Release 1.2.0 targets the full PRD, not a narrow authz-only or foundation-only subset.

It must ship the cyber kernel plus the domain capsule system. AppSec and Pentest are the first hard-gated capsules; other capsules can exist only with explicit maturity labels and must not claim verified effectiveness until their benchmark gates pass.

Release 1.2.0 must ship:

- Operation Ledger;
- Cyber Workspace Graph;
- Evidence And Replay Store;
- Tool Runtime And Adapter Registry;
- Knowledge And Retrieval Service;
- Memory System;
- Permission And Autonomy Controller;
- domain capsule framework;
- benchmark harness.

Release 1.2.0 must include first-class capsules for:

- Pentest Operator;
- AppSec Operator.

Release 1.2.0 must include explicit, maturity-labeled capsules for:

- OSINT Operator;
- Hacking And CTF Operator;
- Cloud, Container And IaC;
- Forensics And Incident Triage.

Release 1.2.0 must not claim:

- autonomous internet-scale pentesting;
- full 0-day research capability;
- zero false positives across cyber;
- replacement for expert human judgment;
- universal effectiveness without domain benchmarks.

Release gate:

- AppSec and Pentest benchmark suites must pass.
- Kernel, graph, evidence, replay, installed-tool inventory, permissioned mode and auto mode tests must pass.
- Any other capsule can ship only if its UI/docs show its maturity level and benchmark status.

## Benchmark Contract

Numasec releases are benchmarked against cyber tasks, not vibes.

Primary command:

```text
cd packages/numasec
bun test --timeout 30000 test/bench/cyber/*.test.ts
```

Optional aliases:

```text
bun run bench cyber
bun run bench cyber --domain appsec
bun run bench cyber --domain pentest
bun run bench cyber --domain osint
bun run bench cyber --domain ctf
```

### Benchmark Suites

#### Pentest Bench

Local fixtures:

- vulnerable web/API lab;
- authz/IDOR lab;
- SSRF or command injection local fixture;
- service enumeration lab.

Scoring:

- verified exploit proof;
- replay works after reset;
- request/command budget respected;
- no promoted false positive.

#### AppSec Bench

Local fixtures:

- vulnerable repository with seeded source/sink bug;
- vulnerable dependency with reachable and unreachable variants;
- secret fixture with real-looking but test-only token;
- IaC/container misconfiguration fixture.

Scoring:

- correct finding classification;
- proof or clear suspected label;
- patch/test generated where requested;
- no raw secret printed.

#### OSINT Bench

Offline source corpus plus optional online mode.

Fixtures:

- fake company domain corpus;
- certificate/source records;
- archived pages;
- GitHub-like repo metadata;
- conflicting source records.

Scoring:

- entity graph correctness;
- source citations;
- confidence calibration;
- passive-mode boundary respected.

#### CTF Bench

Local challenges:

- web;
- crypto;
- forensics;
- reverse/binary warmup;
- pwn only where the lab is stable and safe.

Scoring:

- flag captured;
- solve path replayed from clean workspace;
- exploit/writeup artifact saved.

#### Tool Adapter Bench

Fixtures:

- nmap XML/text;
- nuclei JSON;
- semgrep JSON;
- trivy JSON;
- ffuf JSON;
- HAR;
- pcap/log sample.

Scoring:

- parser correctness;
- graph writes;
- evidence links;
- graceful degradation when tool is absent.

### Benchmark Rules

- Every promoted finding needs evidence.
- Active findings need replay unless domain contract says otherwise.
- Suspected findings must remain suspected.
- False positive promotion is a release blocker for that domain.
- AppSec and Pentest benchmark failures block release 1.2.0.
- Secrets must be redacted by default.
- Benchmarks must run with Bun only.
- Optional installed tools may be skipped with explicit degraded status when absent.
- Scores are recorded per model profile.

## Implementation Plan

### Phase 0: Truth Reset

Tasks:

- replace Authz-first PRD with this PRD;
- update docs so Authz is a capsule, not the product identity;
- add benchmark skeletons for cyber domains;
- add a "claim must map to evidence or benchmark" rule to contributor docs;
- document current tool inventory honestly.

Exit criteria:

- product positioning says Cyber Code CLI;
- no docs claim broad effectiveness without evals;
- benchmark command exists with TODO fixtures.

### Phase 1: Ledger, Graph, Evidence

Tasks:

- add append-only operation ledger;
- add SQLite/Drizzle cyber workspace graph schema;
- add candidate/observed/verified/rejected/stale fact lifecycle;
- add provenance links from graph facts to ledger events and evidence;
- add deterministic graph writers for first-party tools and parsers;
- add LLM candidate-fact ingestion with no confirmed writes;
- add evidence store contracts;
- replace markdown-as-state with agent context pack generation;
- add graph digest rendering for context packing.

Exit criteria:

- operation state survives restart;
- tool actions can write ledger events;
- evidence hashes link to graph entities;
- graph facts are attributable to provenance;
- LLM-created facts are candidate-only;
- context pack summarizes graph state for the agent.

### Phase 2: Tool Runtime And Kali Fusion

Tasks:

- inventory installed tools;
- define tool card format;
- add adapter registry;
- add parsers for top outputs;
- wrap raw terminal with transcripts, risk labels and graph writes;
- update `/doctor` with cyber tool readiness.

Exit criteria:

- Numasec knows which security tools are available;
- absent tools degrade clearly;
- parsed outputs create graph entities;
- raw command transcripts are evidence.

### Phase 3: Knowledge And Memory

Tasks:

- implement knowledge lookup and source caching;
- add CVE/advisory/exploit lookup;
- add operation memory write/manage/retrieve loop;
- add context packer for active operation state;
- add stale-source labeling.

Exit criteria:

- vulnerability claims can cite sources;
- OSINT claims can cite sources;
- stale facts are labeled;
- context packer selects relevant memory.

### Phase 4: Domain Capsules

Tasks:

- implement capsule interface;
- port existing plays into capsule runbooks;
- add Pentest and AppSec as hard-gated capsules;
- add OSINT, CTF/Hacking, Cloud/Container/IaC and Forensics as maturity-labeled capsules;
- define capsule-specific proof contracts;
- expose `runbook` UX.

Exit criteria:

- operator can run Pentest and AppSec end to end;
- outputs land in ledger, graph and evidence;
- weak claims are suspected by default.

### Phase 5: Oracles And Benchmarks

Tasks:

- build local fixtures;
- implement oracle engine;
- add replay checks;
- add scoring;
- record model-profile results.

Exit criteria:

- AppSec and Pentest benchmark suites pass release gates;
- false positive promotion blocks release;
- replay bundles are generated.

### Phase 6: Product Hardening

Tasks:

- tune prompts and tool descriptions;
- improve TUI visibility for graph, evidence and running capsule;
- add report/share contracts;
- add redaction checks;
- add docs for Kali Fusion, model profiles and domain maturity.

Exit criteria:

- fresh developer can run benchmarks;
- fresh operator can run a local lab end to end;
- reports are proof-linked and redacted.

## Acceptance Criteria

Release 1.2.0 is acceptable only when:

- The product is documented as Cyber Code CLI, not authz scanner.
- Pentest and AppSec capsules are implemented and benchmark-gated.
- OSINT, CTF/Hacking, Cloud/Container/IaC and Forensics capsules are present only with explicit maturity labels unless benchmark-gated.
- Operation Ledger records tool actions and decisions.
- Cyber Workspace Graph stores provenance-backed facts, not LLM-maintained prose.
- LLM graph writes are candidate-only.
- Graph facts carry status and provenance.
- Evidence And Replay Store links findings to proof.
- Tool Runtime inventories local security tools.
- Only installed tools are used; no container/lab image is required.
- Tool cards are loaded on demand.
- Raw terminal remains available with transcripts and risk labels.
- Knowledge lookups store sources and freshness.
- Memory is queryable and not markdown-based.
- `numasec.md`, if present, is an agent context pack, not canonical state.
- Permissioned mode supports deny/allow/allow-always.
- Auto mode enforces scope and budgets.
- Reports refuse to promote unsupported claims.
- No raw secrets are printed or persisted by default.
- Benchmarks run with Bun from `packages/numasec`.
- AppSec and Pentest benchmark suites pass.
- Domain maturity is visible in docs and `/doctor`.

## Maturity Levels

Each domain has a maturity level.

Level 0: Available

- basic prompts or tools exist;
- no benchmark claim.

Level 1: Assisted

- capsule can guide an operator;
- evidence capture works;
- suspected findings only.

Level 2: Verified

- capsule has domain oracles;
- benchmark suite passes;
- confirmed findings require proof.

Level 3: Replayable

- replay bundles work from reset;
- false positive gate exists;
- report export is benchmarked.

Level 4: Autonomous Disposable Scope

- bounded auto works in local/disposable targets;
- budgets and kill switch tested.

Level 5: Field Hardened

- real operator feedback;
- multiple model profiles evaluated;
- degraded external tool behavior tested;
- docs match observed performance.

Numasec can be 360-degree in surface area before it is 360-degree in verified maturity. The UI must make that distinction clear.

## Product Metrics

Core metrics:

- benchmark score per domain;
- promoted false positives;
- time to first proof;
- replay success rate;
- tool execution success;
- parser coverage;
- evidence coverage;
- memory retrieval usefulness;
- source citation coverage;
- target requests or commands per proof;
- model cost per proof.

Product metrics:

- proof bundles shared;
- accepted vulnerability reports;
- patches generated and merged;
- operator runbooks completed;
- adapters contributed;
- benchmark PRs added;
- recurring operators.

Do not optimize for raw number of tools, agents or prompts.

## Design Rules

- Prefer one semantic tool with deep behavior over many shallow wrappers.
- Keep raw terminal access because security work is messy.
- Parse tool output into graph state whenever practical.
- Never hide uncertainty behind polished prose.
- Label suspected, verified and replayed separately.
- Store failed attempts.
- Make every high-confidence claim traceable.
- Keep autonomy bounded by scope and budget.
- Do not require target ownership proof in core flows.
- Do not depend on a single model.
- Do not build a universal ontology ahead of evidence.
- Do not launch permanent multi-agent swarms by default.
- Do not load every tool schema into context.
- Do not call a domain effective until its benchmark passes.

## Final Product Shape

Numasec should become:

```text
Cyber Code CLI

Terminal-native.
Kali-fused.
Model-agnostic.
Cyber-model-optimized when available.
Operator-sovereign.
Multi-domain.
Tool-rich but context-disciplined.
Memory-backed.
Knowledge-current.
Evidence-first.
Replay-driven.
Oracle-verified.
Benchmark-gated.
```

The winning product is not the one with the longest list of security tools. It is the one that makes a frontier model behave like a disciplined cyber operator across real workflows: collect context, choose tools, act in scope, parse results, remember what happened, verify claims, replay proof and report honestly.

## Research And Product Anchors

- OpenAI Codex CLI: https://developers.openai.com/codex/cli
- OpenAI Codex product: https://openai.com/codex/
- Claude Code overview: https://code.claude.com/docs/en/overview
- Claude Code agentic loop: https://code.claude.com/docs/en/how-claude-code-works
- OpenAI Aardvark / Codex Security: https://openai.com/index/introducing-aardvark/
- XBOW AI pentesting evaluation: https://xbow.com/blog/ai-pentesting-evaluation-guide
- CAI framework: https://github.com/aliasrobotics/CAI
- HexStrike AI: https://www.hexstrike.com/
- PentestGPT: https://pentestgpt.com/
- PentestGPT paper: https://pentestgpt.com/paper.html
- AutoSecAgent, recursive memory and real-time RAG: https://link.springer.com/article/10.1007/s11227-026-08439-z
- Cybench: https://ee.stanford.edu/cybench-framework-evaluating-cybersecurity-capabilities-and-risks-language-models
- Memory for Autonomous LLM Agents survey: https://arxiv.org/abs/2603.07670
- Hackers or Hallucinators, AutoPT analysis: https://arxiv.org/abs/2604.05719
