# Numasec: Post-Fork Engineering PRD
## From OpenCode Fork to the Claude Code of Cybersecurity

**Version**: 2.0  
**Date**: 2026-03-28  
**Authors**: Francesco Stabile, Copilot (engineering analysis)  
**Scope**: Maintainability strategy, domain customization gap analysis, technical roadmap  

---

## 1. Executive Summary

Numasec started as a Python MCP server with 21 security tools. The decision to fork OpenCode (MIT, TypeScript/Bun, 131k+ stars) transformed it from "just an MCP" into a standalone AI penetration testing terminal — the first of its kind.

**Current state**: The fork is functional. The Python bridge works, 21 security tools are operational, system prompts are rewritten, security-specific agents exist, and the TUI launches. v4.0.0 shipped with 924 tests passing.

**The problem**: The fork is incomplete. After deep analysis of every file in the codebase, I've identified **47 specific items** that are still coding-focused, dead code, or need architectural decisions. More critically, there is no formalized strategy for keeping up with upstream OpenCode changes — and this will become the #1 engineering risk over time.

This document addresses three questions:
1. **How do we keep up with OpenCode updates?** (§2 — Maintainability)
2. **What's still coding-focused that needs to change?** (§3 — Domain Gap)
3. **What's the prioritized plan to close these gaps?** (§4 — Roadmap)

Every claim in this document is backed by specific file paths and code evidence from the codebase analysis.

---

## 2. Maintainability: The Upstream Sync Problem

### 2.1 Current State (Verified)

The repo has a **weekly upstream sync mechanism** already in place:

- **GitHub Action**: `.github/workflows/upstream-sync.yml`
- **Schedule**: Every Monday at 09:00 UTC
- **Upstream**: `https://github.com/sst/opencode.git` (main branch)
- **Mechanism**: Fetches last 50 upstream commits, computes merge base, generates diff report
- **Output**: Creates/updates a GitHub Issue labeled `upstream-sync` with:
  - New commit count and descriptions
  - Changed files filtered by `.ts`, `.tsx`, `.py`
  - Smart recommendations (e.g., "provider/ changes → likely new models, low conflict")

**Git remotes**: Only `origin` (github.com/FrancescoStabile/numasec). No persistent `upstream` remote — the sync workflow adds it transiently.

**Fork history** (from git log):
- `6e57e05` — "Phase 0+1: Fork OpenCode as agent/, rename to numasec, add security tools"
- `7a3457d` through `260aa4d` — Phases 1-5: systematic domain replacement
- `31e2dad` — "Phase 6: Remove all brendonovich/opencode references"
- Current: `ced8898` — v4.0.0 release

### 2.2 Assessment: What Works, What Doesn't

**What works**:
- The weekly issue creation is a good signal/detection mechanism
- The file-change categorization helps triage

**What doesn't work**:
- There is **no automated merge or cherry-pick** — the issue is purely informational
- There is **no tracking of which upstream commits have been reviewed/applied/skipped**
- There is **no test to validate that a cherry-pick doesn't break numasec**
- The codebases will diverge faster as numasec adds security-specific code to shared files

### 2.3 Recommended: Three-Layer Sync Architecture

The upstream sync problem has three distinct layers, each needing a different strategy:

#### Layer 1: "Safe Zone" — Auto-mergeable (Low Risk)

These upstream directories have **zero numasec modifications** and can be synced with minimal review:

| Upstream Path | What It Contains | Risk |
|--------------|-----------------|------|
| `src/provider/` | LLM provider adapters (AI SDK wrappers) | Very Low |
| `src/auth/` | OAuth flows, API key management | Very Low |
| `src/effect/` | Effect-TS infrastructure utilities | Very Low |
| `src/id/` | ULID generation | None |
| `src/format/` | Text formatting utilities | None |
| `src/bus/` | Event bus / pub-sub | Low |
| `src/env/` | Environment variable loading | Low |
| `packages/ui/` | UI component library | Low |
| `packages/plugin/` | Plugin framework | Low |

**Strategy**: Create a script (`script/upstream-merge-safe.sh`) that:
1. Fetches upstream
2. Cherry-picks commits touching ONLY safe-zone files
3. Runs `bun typecheck` and `bun test` to validate
4. Creates a PR (not auto-merge) for quick human review

#### Layer 2: "Review Zone" — Cherry-pick with care (Medium Risk)

These have numasec modifications but upstream changes are usually compatible:

| Upstream Path | Numasec Changes | Sync Approach |
|--------------|----------------|---------------|
| `src/session/` | Prompt files rewritten; session logic untouched | Cherry-pick non-prompt changes |
| `src/config/` | Config schema extended (security fields) | Cherry-pick, resolve schema conflicts |
| `src/storage/` | New tables added (findings, targets, etc.) | Cherry-pick migrations carefully |
| `src/mcp/` | MCP client mostly untouched | Cherry-pick |
| `src/server/` | Hono server mostly untouched | Cherry-pick |
| `src/permission/` | Permission schema extended | Cherry-pick, test permission eval |
| `src/plugin/` | Plugin loading untouched | Cherry-pick |
| `src/skill/` | Skill loading untouched, new skills added | Cherry-pick |

**Strategy**: Weekly issue (existing) + manual cherry-pick with `git cherry-pick -x` (records source commit). Maintain a `UPSTREAM_LOG.md` tracking:
```
| Upstream Commit | Date | Applied? | Notes |
|----------------|------|----------|-------|
| abc1234 | 2026-03-20 | ✅ Yes | Provider: added Grok 3 |
| def5678 | 2026-03-20 | ⏭ Skip | Tool: new edit tool (not applicable) |
| ghi9012 | 2026-03-20 | ✅ Yes | Session: compaction improvement |
```

#### Layer 3: "Diverged Zone" — Never sync (High Risk / Not Applicable)

These have been fundamentally replaced or are security-specific:

| Upstream Path | Why It Diverged |
|--------------|----------------|
| `src/tool/` | Entire tool registry replaced with security tools |
| `src/agent/` | Agent definitions rewritten for pentesting |
| `src/session/prompt/` | All prompts rewritten for PTES |
| `src/command/` | Commands replaced with /target, /findings, /report, etc. |
| `src/bridge/` | Numasec-specific Python bridge (doesn't exist upstream) |
| `src/lsp/` | Stubbed out |
| `src/ide/` | REMOVED — terminal-only tool |
| `src/worktree/` | REMOVED — not relevant for pentesting |

**Strategy**: Monitor upstream for architectural changes (e.g., "tool system v2"), but never auto-merge. If upstream makes a fundamental change to the tool dispatch system, manually port the architecture.

### 2.4 Recommended: Upstream Sync Workflow Improvements

**Immediate** (this week):
1. Add a persistent `upstream` remote: `git remote add upstream https://github.com/sst/opencode.git`
2. Create `UPSTREAM_LOG.md` in repo root to track cherry-pick decisions
3. Modify `.github/workflows/upstream-sync.yml` to categorize changes into Safe/Review/Diverged zones

**Short-term** (next 2 weeks):
4. Create `script/upstream-merge-safe.sh` for auto-cherry-picking Safe Zone changes
5. Add a CI step that runs `bun typecheck && bun test` on any cherry-pick PR
6. Tag the exact upstream commit the fork is based on: `git tag upstream-base <commit>`

**Medium-term** (next month):
7. Consider pinning upstream to release tags (not main branch) for stability
8. Evaluate extracting "Safe Zone" packages as git subtrees for cleaner separation

### 2.5 New AI Models: How They Get Into Numasec

This is actually the **easiest** part. New AI models arrive through two paths:

**Path A: Vercel AI SDK updates** (most common)
- OpenCode uses `@ai-sdk/*` provider packages (OpenAI, Anthropic, Google, etc.)
- When a new model launches, the AI SDK team adds it (usually within days)
- Numasec just bumps the `@ai-sdk/*` version in `package.json` → new model available
- This is a `bun update @ai-sdk/openai` one-liner

**Path B: New provider entirely** (rare)
- If a completely new provider appears (e.g., "xAI Grok"), upstream OpenCode adds it
- This falls in the "Safe Zone" (Layer 1) — the `src/provider/` directory
- Cherry-pick the upstream commit that adds the new provider adapter

**Risk level**: Very low. The provider abstraction via AI SDK means new models are almost always a dependency bump, not a code change.

---

## 3. Domain Gap Analysis: What's Still Coding-Focused

After auditing every directory in `agent/packages/numasec/src/` and all supporting packages, here is the **complete inventory** of items that are still OpenCode-default or coding-focused.

### 3.1 Severity: CRITICAL (Breaks the security product identity)

#### C1. Command Template: `initialize.txt`
- **File**: `agent/packages/numasec/src/command/template/initialize.txt`
- **Problem**: Creates `AGENTS.md` file analyzing a *codebase* for build/lint/test commands and code style guidelines. Pure coding assistant behavior.
- **Evidence**: "Please analyze this codebase and create an AGENTS.md file containing: 1. Build/lint/test commands... 2. Code style guidelines..."
- **Decision ✅**: Rewrite as **Security Engagement Init** → "Analyze the target application and create an AGENTS.md file containing: 1. Target architecture and technology stack 2. Attack surface summary 3. Authentication mechanisms 4. Known security configurations"

#### C2. Command Template: `review.txt`
- **File**: `agent/packages/numasec/src/command/template/review.txt` (~200 lines)
- **Problem**: Complete code review system — reviewing git diffs for logic bugs, style violations, naming conventions. This is the core OpenCode code review experience.
- **Evidence**: "You are a code reviewer. Your job is to review code changes and provide actionable feedback... Logic errors, off-by-one mistakes, incorrect conditionals..."
- **Decision ✅**: Rewrite as **Secure Code Review** — analyze code changes specifically for security vulnerabilities (injection sinks, auth bypasses, crypto misuse, hardcoded secrets, input validation gaps). High-value AppSec feature: find vulns with scanners, then review remediation PRs.

#### C3. Console Marketing Copy: "Coding Agent" Everywhere
- **File**: `agent/packages/console/app/src/i18n/en.ts` (and all 15+ language files)
- **Problem**: 36+ instances of "coding agent" in the marketing/console UI:
  - `"app.meta.description": "Numasec - The open source coding agent."`
  - `"temp.hero.title": "The AI coding agent built for the terminal"`
  - `"home.hero.title": "The open source AI coding agent"`
  - `"home.what.lsp.title": "LSP enabled"` (coding feature promoted)
  - Entire "Zen" section: "Reliable optimized models for coding agents" (20+ references)
  - `"zen.faq.a2": "You wouldn't use a butter knife to cut steak, don't use poor models for coding."`
- **Action**: Complete i18n rewrite for all language files. Replace "coding agent" → "penetration testing platform", remove Zen/Go coding branding, remove LSP/editor references. Add security-specific value props (OWASP coverage, PTES methodology, 21 security scanners).

#### C4. Root Package Description
- **File**: `agent/package.json`
- **Problem**: `"description": "AI-powered development tool"`
- **Action**: Change to `"AI-powered penetration testing platform"` or `"The AI terminal for cybersecurity"`

### 3.2 Severity: HIGH (Functional coding features that shouldn't exist)

#### H1. GitHub Integration: Code Review Mode
- **File**: `agent/packages/numasec/src/cli/cmd/github.ts`
- **Problem**: Lines ~793-1609 contain full PR code review functionality — analyzing diffs, suggesting code improvements, commenting on code style. This was a core OpenCode feature.
- **Action**: Rewrite as **Secure PR Review** — scan PR diffs for security issues only (new SQL queries without parameterization, removed auth checks, exposed secrets, new endpoints without input validation). This transforms a coding feature into a security-differentiated feature.

#### H2. Git Worktree Management
- **File**: `agent/packages/numasec/src/worktree/`
- **Problem**: Complete git worktree create/remove/reset system. Developer productivity feature irrelevant for pentesting.
- **Decision ✅**: **Remove entirely**. Clean up imports in the project system that reference it.

#### H3. IDE Integration (VS Code / Cursor)
- **File**: `agent/packages/numasec/src/ide/index.ts`
- **Problem**: Active VS Code / Cursor / Windsurf / VSCodium detection and extension installation (`sst-dev.numasec` extension).
- **Decision ✅**: **Remove entirely**. Numasec is terminal-only, no editor integration.

#### H4. Share System Points to OpenCode
- **File**: `agent/packages/numasec/src/share/share-next.ts`
- **Problem**: Session sharing falls back to `https://opncd.ai` (OpenCode's domain). Shared sessions would go to OpenCode's servers, not numasec's.
- **Action**: Either:
  - Set up numasec's own sharing endpoint
  - Disable sharing entirely (`NUMASEC_DISABLE_SHARE=true` already works as a flag)
  - At minimum, change the fallback URL to prevent data leaking to OpenCode

#### H5. Feature Flags with Coding References
- **File**: `agent/packages/numasec/src/flag/flag.ts`
- **Problem**: Flags like `NUMASEC_DISABLE_CLAUDE_CODE`, `NUMASEC_DISABLE_CLAUDE_CODE_PROMPT`, `NUMASEC_DISABLE_CLAUDE_CODE_SKILLS` reference "Claude Code" integration. Also `NUMASEC_EXPERIMENTAL_LSP_TOOL` for LSP as a tool.
- **Action**: Remove Claude Code-specific flags (they're OpenCode compatibility layers). Keep `NUMASEC_EXPERIMENTAL_LSP_TOOL` but default to disabled.

#### H6. Dead Packages: Desktop Apps
- **Files**: `agent/packages/desktop/` (Tauri), `agent/packages/desktop-electron/` (Electron)
- **Problem**: Both desktop app packages are fully scaffolded but **never built, never deployed, not in CI/CD**. They're dead code adding monorepo complexity.
- **Action**: **Remove both directories**. If numasec needs a desktop app later, start fresh with current architecture. The Tauri setup is already outdated.

### 3.3 Severity: MEDIUM (Misaligned defaults / dead weight)

#### M1. Project Concept: Repo vs. Target
- **File**: `agent/packages/numasec/src/project/`
- **Problem**: A "project" is defined as a git repository (discovered by walking up to `.git`). The project icon is a favicon, the project name comes from git. For a pentesting tool, a "project" should be an **engagement** or **target** — not a code repository.
- **Action**: Long-term, rebrand "project" → "engagement" with target URL as the identifier. Short-term, this is functional and non-blocking — the project system works fine as a session container.

#### M2. Snapshot/Undo System
- **File**: `agent/packages/numasec/src/snapshot/`
- **Problem**: The snapshot system creates filesystem checkpoints for undo/redo of file changes. Since numasec doesn't edit files, this system is mostly unused weight.
- **Action**: **Leave as-is**. The snapshot system is deeply integrated with the session engine and removing it risks breaking undo/redo for session management. It's inert overhead, not wrong behavior.

#### M3. External Auth Plugins
- **File**: `agent/packages/numasec/src/plugin/index.ts`
- **Problem**: Imports `opencode-gitlab-auth` and `opencode-poe-auth` npm packages. OpenCode ecosystem plugins.
- **Decision ✅**: **Remove both**. GitLab and Poe are not relevant auth providers for a security tool.

#### M4. Web/Docs Site Content
- **File**: `agent/packages/web/` (Astro + Starlight)
- **Problem**: The documentation site likely contains coding-focused content inherited from OpenCode.
- **Decision ✅**: Deployment shut down (per D3). Content rewrite deferred to Phase 4 when ready to re-deploy.

#### M5. Orphaned Theme File
- **File**: `agent/packages/numasec/src/cli/cmd/tui/context/theme/opencode.json`
- **Problem**: Theme file exists but is NOT registered in DEFAULT_THEMES (not imported in theme.tsx).
- **Decision ✅**: Delete file.

#### M6. Enterprise Package: Empty Shell
- **File**: `agent/packages/enterprise/`
- **Problem**: Deployed to production but renders "Hello World". Only has a `/api/share` route.
- **Decision ✅**: **Remove deployment** (per D3 pattern). Keep source in repo. Costs hosting for zero value.

#### M7. Slack Integration
- **File**: `agent/packages/slack/`
- **Problem**: Fully implemented Slack bot but not deployed, not in CI/CD.
- **Decision ✅**: **Remove**. Not in the product roadmap.

### 3.4 Severity: LOW (Polish items)

#### L1. `agent/README.md` Line 3
- **Problem**: "Terminal UI for numasec. TypeScript/Bun monorepo, forked from OpenCode (MIT)."
- **Action**: This is fine for transparency. Keep but consider softening to: "Terminal UI for numasec. Built on TypeScript/Bun."

#### L2. Console i18n: 15+ Language Files
- **Problem**: If C3 is fixed for `en.ts`, all other language files (de, fr, es, zh, ja, ko, ru, etc.) need the same changes.
- **Action**: Fix `en.ts` first, then batch-process other languages. Consider dropping non-English languages initially (the FORK_PRD.md already suggested this).

#### L3. "Getting Started" UX in Web App
- **File**: `agent/packages/app/src/i18n/en.ts`
- **Problem**: `"home.empty.description": "Get started by opening a local project"` — implies "project" = code project.
- **Action**: Change to "Get started by setting a target" or "Start a new security assessment".

---

## 4. Strategic Decisions — Finalized

All decisions confirmed on 2026-03-28.

### D1. Secure Code Review → ✅ KEEP & TRANSFORM

**Decision**: Transform `/review` command and GitHub PR integration into **Secure Code Review**.

**Rationale**: The review system is lightweight (101-line template + ~57 lines of analysis-agnostic GitHub integration). Converting to security review requires only rewriting `review.txt` and changing ~3 lines of code. The GitHub integration (fetch PR data → send to model → post comment) works identically for security reviews.

**Value**: Positions numasec for the AppSec workflow — find vulnerabilities with scanners, then review PRs for remediation correctness + scan new code for injection sinks, auth bypasses, secret exposure, crypto misuse. Differentiates numasec as both runtime scanner AND SAST-lite.

**Effort**: ~2 hours (rewrite template + update description).

### D2. Desktop Apps → ✅ REMOVE

**Decision**: Delete both `packages/desktop/` (Tauri) and `packages/desktop-electron/` (Electron).

**Rationale**: Neither package is built, deployed, or referenced in CI/CD. The TUI is the product. Dead code adding monorepo complexity. If a desktop app is needed later, start fresh.

### D3. Console/Web → ✅ SHUT DOWN

**Decision**: Take down deployed console (numasec.ai) and web (docs.numasec.ai) services. Keep code in repo but remove from active deployment.

**Rationale**: The console is OpenCode's SaaS infrastructure (dashboard, Stripe billing, team management). The numasec TUI does NOT use any of it — it runs 100% standalone. The marketing copy says "The open source AI coding agent" across 36+ instances. Having a live site promoting numasec as a "coding agent" actively harms the product identity. The infrastructure may be valuable later for SaaS monetization, but must be rewritten for security before being re-deployed.

**Action**:
1. Remove console/web from SST deployment (`infra/console.ts`, `infra/app.ts`)
2. Keep the source code in repo for future reuse
3. When ready to launch a public site, rewrite all content for security/pentesting

### D4. Session Sharing → ✅ DISABLE

**Decision**: Disable session sharing by default. Set `NUMASEC_DISABLE_SHARE=true` as the default.

**Rationale**: The share system falls back to `opncd.ai` (OpenCode's servers). Sending pentest session data (findings, credentials, target info) to a third-party server is a data leak risk. Security assessments must stay local by default.

**Future**: If team collaboration is needed, build numasec's own sharing infrastructure.

### D5. Project → Engagement Rename → ✅ LEAVE AS-IS

**Decision**: Keep the "project" abstraction unchanged.

**Rationale**: The project system is an internal abstraction that auto-detects the git repo root and groups sessions. Users never see the word "project" in the TUI — it's only visible in the WebUI sidebar. The system is deeply integrated (~15 files, DB schema, config). Renaming would be a large refactor with zero user-visible impact in the TUI. If the concept of "engagement" becomes important, build it as a layer on top of projects.

---

## 5. Prioritized Roadmap

### Phase 1: Immediate Security Hardening (This Week)

| # | Item | Severity | Effort | Files |
|---|------|----------|--------|-------|
| 1 | Disable session sharing (default NUMASEC_DISABLE_SHARE=true) | HIGH | 10 min | `flag/flag.ts` or config defaults |
| 2 | Delete orphaned `opencode.json` theme | LOW | 30 sec | 1 file delete |
| 3 | Fix root package.json description | CRITICAL | 30 sec | `agent/package.json` |
| 4 | Add persistent upstream remote + UPSTREAM_LOG.md | MAINT | 15 min | git config + new file |
| 5 | Fix "Get started by opening a local project" text | LOW | 2 min | `app/src/i18n/en.ts` |

### Phase 2: Domain Completion (Next 2 Weeks)

| # | Item | Severity | Effort | Notes |
|---|------|----------|--------|-------|
| 6 | Rewrite `initialize.txt` as Security Engagement Init | CRITICAL | 2 hrs | Confirmed — target arch, attack surface, auth mechanisms |
| 7 | Rewrite `review.txt` as Secure Code Review | CRITICAL | 2 hrs | Confirmed — injection sinks, auth bypass, secret exposure |
| 8 | Update GitHub integration description for security PR review | HIGH | 1 hr | Confirmed — ~3 lines of code, logic is agnostic |
| 9 | Remove `desktop/` and `desktop-electron/` packages | HIGH | 1 hr | Confirmed — delete dirs + update monorepo config |
| 10 | Remove worktree system (`src/worktree/`) | HIGH | 2 hrs | Confirmed — remove entirely + clean up project imports |
| 11 | Remove IDE integration (`src/ide/`) | HIGH | 1 hr | Confirmed — numasec is terminal-only |
| 12 | Shut down console/web/enterprise deployments | CRITICAL | 2 hrs | Confirmed — remove from SST infra, keep source |
| 13 | Remove Claude Code feature flags | HIGH | 30 min | See H5 |
| 14 | Remove external auth plugins (opencode-gitlab-auth, opencode-poe-auth) | MEDIUM | 30 min | Confirmed — not relevant providers |
| 15 | Remove Slack integration package | MEDIUM | 30 min | Confirmed — not in roadmap |

### Phase 3: Polish & Infrastructure (Next Month)

| # | Item | Severity | Effort | Notes |
|---|------|----------|--------|-------|
| 16 | Create upstream-merge-safe.sh script | MAINT | 4 hrs | See §2.4 |
| 17 | Enhance upstream-sync.yml with zone categorization | MAINT | 2 hrs | See §2.4 |
| 18 | Delete orphaned opencode.json theme | LOW | 30 sec | See M5 |

### Phase 4: Differentiation (Next Quarter)

| # | Item | Category | Effort | Notes |
|---|------|----------|--------|-------|
| 19 | Findings sidebar in TUI (from FORK_PRD.md §7.1) | UX | 20 hrs | Not yet implemented |
| 20 | OWASP coverage status bar in TUI | UX | 8 hrs | Not yet implemented |
| 21 | Attack chain visualization in TUI | UX | 16 hrs | Not yet implemented |
| 22 | Rewrite console/web content for security (when ready to re-deploy) | CONTENT | 24 hrs | Full i18n rewrite for 15 languages |
| 23 | Numasec sharing infrastructure (if team features needed) | INFRA | 40 hrs | D4 — disabled for now, build own later |
| 24 | VS Code extension for security findings | PLATFORM | 40 hrs | Repurpose sdks/vscode/ |

---

## 6. Upstream Sync: Concrete Process

### When OpenCode Releases a New Version

```
1. Monday: upstream-sync.yml fires → creates GitHub Issue
   │
2. Read the issue. Changes are categorized:
   │
   ├── Safe Zone (provider/, auth/, effect/, ui/, plugin/)
   │   └── Run: script/upstream-merge-safe.sh
   │       └── Creates PR with cherry-picked commits
   │       └── CI runs typecheck + tests
   │       └── Review + merge (should be quick)
   │
   ├── Review Zone (session/, config/, storage/, mcp/, server/)
   │   └── Manual cherry-pick with: git cherry-pick -x <commit>
   │   └── Resolve conflicts, test, PR
   │   └── Log decision in UPSTREAM_LOG.md
   │
   └── Diverged Zone (tool/, agent/, prompt/, command/, bridge/)
       └── Read upstream diff for architectural insights
       └── Decide: port the concept? ignore? adapt?
       └── Log decision in UPSTREAM_LOG.md
   │
3. Update UPSTREAM_LOG.md with all decisions
4. Tag: git tag upstream-sync-YYYY-MM-DD
```

### When a New AI Model Launches

```
1. Check if AI SDK already supports it:
   └── Usually yes within days of model launch
   └── bun update @ai-sdk/<provider>
   └── Done.

2. If new provider entirely:
   └── Check upstream OpenCode for provider adapter
   └── Cherry-pick from Safe Zone
   └── Or write adapter (AI SDK makes this ~50 lines)

3. No numasec-specific work needed:
   └── Provider abstraction handles model routing
   └── Config: model: "provider/model-name"
   └── User can use new model immediately
```

---

## 7. What's Already Done Right (Verified)

To be fair to the work already done, here's what the fork got RIGHT:

| Component | Status | Evidence |
|-----------|--------|----------|
| System prompts | ✅ Fully rewritten | `session/prompt/default.txt` — PTES 5-phase methodology |
| Tool registry | ✅ All 21 security tools | `tool/registry.ts` — no coding tools remain |
| Agent definitions | ✅ All security-focused | `agent/agent.ts` — pentest, recon, scanner, analyst, reporter, explore |
| LSP | ✅ Stubbed out | `lsp/server.ts` — `export const LSPServer = {}` |
| File editing tools | ✅ Removed | No write/edit/multiedit/apply_patch in registry |
| Security DB schema | ✅ Complete | Drizzle: FindingTable, TargetTable, CredentialTable, CoverageTable |
| Custom commands | ✅ Security-focused | /target, /findings, /report, /coverage, /creds, /evidence |
| Skills | ✅ All security | api-security, auth-testing, owasp, ptes, web-injection |
| Python bridge | ✅ Working | JSON-RPC over stdio, auto-setup with uv |
| Install script | ✅ Working | Bun + uv + launcher at ~/.local/bin/numasec |
| Upstream monitoring | ✅ Weekly | GitHub Action creates issues with diff analysis |
| UI prompt examples | ✅ Security-focused | 25 security-specific examples in app i18n |
| Themes | ✅ numasec.json | Custom security theme with hacker-green palette |
| Permission system | ✅ Security-tuned | Edit tools denied, bash restricted by command pattern |

---

## 8. Risk Matrix

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Upstream OpenCode makes breaking change to session engine | HIGH | MEDIUM | Layer 2 sync process + comprehensive test suite |
| AI SDK major version bump breaks provider adapters | HIGH | LOW | Pin versions, test on upgrade, AI SDK has good BC |
| Effect-TS breaking changes | HIGH | LOW | Already on beta; Effect team prioritizes BC |
| opentui breaking changes | MEDIUM | MEDIUM | Pin version; TUI is relatively stable |
| Shut-down console/web still cached/indexed by search engines | LOW | MEDIUM | Add robots.txt noindex, redirect to GitHub repo |
| Session sharing accidentally re-enabled leaks pentest data | CRITICAL | LOW | Default disabled + code review on share-related PRs |
| Numasec diverges so far from OpenCode that upstream sync becomes impractical | MEDIUM | HIGH (18+ months) | Accept this. Upstream sync has diminishing returns as the product matures. The goal is to capture provider updates and bug fixes, not feature parity. |

---

## 9. Architecture Diagram: Final State

```
┌──────────────────────────────────────────────────────────────┐
│                    User's Terminal                             │
│                                                                │
│  $ numasec                                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ ☠ numasec   Target: https://target.com:443   pentest    │  │
│  │ Coverage: ████████░░ 80%   Findings: 7 (2C 3H 2M)      │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │                                                          │  │
│  │  TypeScript TUI (Bun + SolidJS + opentui)               │  │
│  │  ├─ Session Engine (from OpenCode, kept in sync)         │  │
│  │  ├─ Provider Layer (AI SDK, 16+ LLM providers)          │  │
│  │  ├─ Agent Framework (pentest, recon, scanner, analyst)   │  │
│  │  ├─ Permission System (scope enforcement)                │  │
│  │  └─ Config / Plugin / Skill (extensible)                 │  │
│  │                                                          │  │
│  │  ┌─ Python Bridge (JSON-RPC over stdio) ──────────────┐ │  │
│  │  │                                                     │ │  │
│  │  │  numasec Python Worker                              │ │  │
│  │  │  ├─ 21 Security Scanners                            │ │  │
│  │  │  ├─ 34 Knowledge Base Templates                     │ │  │
│  │  │  ├─ Finding Auto-Enrichment (CWE/CVSS/OWASP)       │ │  │
│  │  │  ├─ Report Generation (SARIF/HTML/MD)               │ │  │
│  │  │  └─ Session State (SQLite)                          │ │  │
│  │  └────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  Alternative mode: $ numasec --mcp                             │
│  └─ Exposes same 21 tools as MCP server for Claude Code, etc. │
└──────────────────────────────────────────────────────────────┘
```

---

## 10. Measuring Success

### Short-term (1 month)
- [ ] Session sharing disabled by default
- [ ] Console/web deployments taken down
- [ ] Dead packages (desktop, desktop-electron) removed
- [ ] `review.txt` rewritten as Secure Code Review
- [ ] `initialize.txt` rewritten for security engagement setup
- [ ] UPSTREAM_LOG.md tracking all sync decisions
- [ ] At least one upstream sync completed using the 3-layer process

### Medium-term (3 months)
- [ ] Zero "coding agent" text in any active surface (TUI, install script, CLI help)
- [ ] Worktree system disabled, Claude Code flags removed
- [ ] TUI findings sidebar implemented
- [ ] First 3 upstream syncs completed smoothly
- [ ] Upstream-merge-safe.sh script operational

### Long-term (6 months)
- [ ] Upstream sync is a routine 30-minute weekly process
- [ ] numasec is recognized as a distinct product, not an OpenCode fork
- [ ] Console/web rewritten and re-deployed for security (if SaaS path chosen)
- [ ] 3+ community security skills published (SKILL.md)
- [ ] End-to-end benchmark against Juice Shop, DVWA, WebGoat

---

*This document is based on analysis of every file in the numasec repository as of 2026-03-28. All file paths, line numbers, and code references were verified against the actual codebase.*
