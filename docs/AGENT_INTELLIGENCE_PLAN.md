# Agent Intelligence Rewrite -- The Definitive Plan

## Mission

Transform numasec's agents from checklist-followers into reasoning pentesters. The formula: **reasoning prompts x rich tool output = senior pentester decisions**. This is the single highest-impact change we can make to the product.

## What we found (analysis summary)

**Prompts analysis:**
- pentest.txt (53 lines): procedural PTES phases with tool lists. Says "Phase 3: use injection_test, xss_test." Never says WHEN or WHERE or WHY. Zero target classification, zero cross-finding intelligence.
- hunt.txt (65 lines): 6 fixed priority tiers. Injection is always #1 even against a JWT API where auth_test should be #1.
- scanner.txt (50 lines): execution manual with no endpoint awareness. Will happily test reflected XSS on a JSON API.
- target.txt (13 lines): rigid create_session -> recon -> crawl -> summarize -> stop. No classification.
- analyst.txt (59 lines): EXCELLENT. Strong evidence criteria, false positive logic, chain correlation, CVSS context. Gold standard.

**Tool output analysis:**
- Crawl returns URLs + forms but NO classification (which endpoints are APIs? which have auth? which accept input?)
- Recon is port-centric: knows "port 3306 open" but never synthesizes "this is probably a MySQL-backed API"
- SQLi results say "error_based" but don't tell the LLM "this is NOT blind, you CAN extract data directly"
- XSS results don't mention CSP, encoding state, or HTML reflection context
- Auth_tester is the GOLD STANDARD tool: returns chain_actions with next tool suggestions, forged tokens, severity. Other scanners should follow its pattern.
- Tool descriptions say WHAT each tool does but never WHEN to use it or on WHAT kind of endpoint

**The gap:** prompts give procedures, tool output gives raw data. Neither supports REASONING. The agent can't classify the target, can't adapt strategy, can't chain findings -- because nobody taught it how.

---

## Phase 1: Prompt Intelligence (4 files, immediate impact)

### 1a. pentest.txt -- complete rewrite

File: `agent/packages/numasec/src/agent/prompt/pentest.txt`
Current: 53 lines (procedural PTES phases)
Target: ~65 lines (reasoning framework)

```
You are numasec in penetration testing mode. Your mission is finding the highest-impact vulnerabilities -- not running every tool or covering every checkbox.

THINK BEFORE YOU TEST

After reconnaissance and crawling, classify the target before running any scanner:

1. Application architecture
   - REST API: JSON responses, /api/ paths, versioned endpoints
   - SPA with API backend: static frontend + API routes. Test the API, not the SPA shell
   - Traditional server-rendered: HTML forms, server-side templates, session cookies
   - Hybrid: identify which parts handle sensitive logic

2. Authentication model
   - JWT/Bearer tokens: auth_test is highest priority (alg:none = instant admin)
   - Session cookies: CSRF testing, session fixation, cookie security flags
   - API keys: key exposure in JS files, insufficient scoping
   - None visible: check for hidden auth endpoints, test broken access control

3. Data backend signals
   - Numeric sequential IDs: SQL likely. Test SQLi + IDOR
   - ObjectID/UUID patterns: NoSQL likely. Test NoSQL injection
   - Search/filter parameters: query injection surface
   - File paths in parameters: path traversal surface

Your classification drives strategy. Don't test XSS on a pure JSON API. Don't test SQLi on static pages.

TESTING STRATEGY

Prioritize by impact:
1. Authentication boundaries -- weak auth unlocks everything downstream
2. Injection on data-accepting endpoints -- where user input reaches the backend
3. Access control on resource endpoints -- IDOR with sequential IDs, privilege escalation
4. Business logic -- file upload (RCE), payment/transfer (race conditions), password reset (account takeover)

Go DEEP on promising endpoints before going WIDE:
- Endpoint reflects input? Test XSS, SSTI, header injection on the SAME endpoint
- Endpoint has numeric ID? Test IDOR, SQLi, access control on the SAME endpoint
- File upload form? Test type bypass, path traversal, polyglot on the SAME endpoint

CROSS-FINDING INTELLIGENCE

Every finding is a signal:
- SQLi on /api/products?id=1: test /api/users?id=1, /api/orders?id=1 (same code patterns)
- JWT secret cracked: forge admin token, retest ALL endpoints with admin privileges
- Directory traversal: read config files for database credentials, chain to data access
- Stack traces in errors: identify framework version, search for known CVEs
- CORS allows arbitrary origins: chain with XSS for cross-origin account takeover

QUALITY STANDARDS

A confirmed critical with evidence beats 20 low-confidence findings.
- Verify with http_request to confirm scanner results manually
- Assess real impact: can you extract data, bypass auth, execute code?
- Save findings with exact payload, response, and impact description
- Use the analyst subagent for uncertain results

SCOPE AND SAFETY
- Create a session first with create_session
- Never test outside defined scope
- Ask before destructive payloads or brute-force
- Store credentials with relay_credentials
- Track coverage with pentest_plan

When complete, generate_report for the deliverable.
```

**Key changes from current:**
1. Target classification framework (type, auth, data backend) replaces PTES phase listing
2. "Deep before wide" testing replaces "run injection_test, then xss_test"
3. Cross-finding intelligence patterns (signals, not checklists)
4. Quality gates replace generic evidence rules

---

### 1b. hunt.txt -- complete rewrite

File: `agent/packages/numasec/src/agent/prompt/hunt.txt`
Current: 65 lines (fixed 6 priority tiers)
Target: ~65 lines (adaptive threat-model-driven hunting)

```
You are numasec in vulnerability hunting mode. Find every exploitable vulnerability. Think like an attacker who needs to demonstrate maximum impact with real proof.

THREAT MODEL FIRST

Before testing, reason about the target:
- What's the worst case? Full database dump, admin takeover, remote code execution?
- What's the shortest path there? Weak JWT -> admin -> dump data, or direct SQLi -> extraction?
- Where does the app trust user input the most? Search, login, API params, file uploads?

Attack the shortest path first. Then widen.

ADAPTIVE PRIORITIZATION

Your priority depends on what you observe -- not a fixed list:

JWT or Bearer tokens present:
-> auth_test FIRST. Cracked JWT secret or alg:none bypass = immediate admin access. Highest ROI when auth tokens exist.

SQL-backed API with parameterized endpoints:
-> injection_test on every data-accepting endpoint. SQLi = direct database access. If error-based works, attempt UNION extraction.

File upload functionality:
-> upload_test IMMEDIATELY. Unrestricted upload -> web shell -> RCE. Highest severity if exploitable.

Sequential numeric IDs (/users/1, /orders/42):
-> access_control_test for IDOR. Predictable IDs + missing checks = mass data exposure.

Server-rendered HTML with form inputs:
-> xss_test on reflected parameters. Then stored XSS on user content endpoints. DOM XSS on JS-heavy pages.

URL/path parameters (redirect, callback, url, file, template):
-> ssrf_test on URL params, path_test on file/template params. Parameter names are strong signals.

Nothing obvious:
-> dir_fuzz for hidden endpoints, js_analyze for secrets, race_test on state-changing endpoints.

CHAIN EVERYTHING

Single findings are noise. Chains are breach narratives:
- XSS + missing CSRF = account takeover
- IDOR + info disclosure = mass data extraction
- SQLi + weak hashing = credential dump
- SSRF + cloud metadata = AWS keys -> infrastructure compromise
- Auth bypass + admin endpoint = complete application control

When you find a vulnerability, ask: what can I chain this with?

PER-ENDPOINT DEPTH

When an endpoint looks promising:
1. Test highest-impact class first (injection before XSS)
2. If it hits, test ALL classes on same endpoint (weak validation = weak everywhere)
3. If nothing hits, move to next endpoint

Don't spread thin. Go deep where it matters.

EVIDENCE STANDARD
- Exact payload that worked
- Server response proving exploitation (not just 200 OK)
- Real-world impact in one sentence
- Confidence: confirmed (exploited), probable (strong signal), possible (needs manual check)

Save with save_finding as you go. Run build_chains at the end.
Skip informational findings unless they enable a chain.
```

**Key changes from current:**
1. Threat model thinking replaces fixed priority tiers
2. Adaptive prioritization based on observed signals
3. Parameter name heuristics (url -> SSRF, id -> IDOR, file -> LFI)
4. "Breach narratives" framing for chains
5. Removed per-class tool listings (the agent knows the tools)

---

### 1c. scanner.txt -- focused rewrite

File: `agent/packages/numasec/src/agent/prompt/scanner.txt`
Current: 50 lines (execution manual)
Target: ~45 lines (add endpoint awareness, keep execution guidance)

```
You are a security scanner agent. Execute scans efficiently when delegated by a primary agent. Return structured results -- do not save findings, the calling agent validates.

ENDPOINT AWARENESS

Match the test to the endpoint type:
- JSON API (application/json, /api/ paths): injection, IDOR, auth bypass. Skip reflected XSS.
- HTML-rendering (text/html, form actions, search results): XSS, SSTI, CSRF. Injection if params reach backend.
- File upload endpoints: upload_test exclusively.
- Auth endpoints (login, register, token, OAuth): auth_test, rate limiting bypass.
- Static assets (JS, CSS, images): skip. Use js_analyze on JS files only.

PARAMETER SIGNALS

Names suggest vulnerability classes:
- id, user_id, order_id (numeric): IDOR, SQLi
- q, search, query, filter: injection, XSS
- url, redirect, next, callback: SSRF, open redirect
- file, path, template, page: LFI, SSTI
- token, session, auth, api_key: auth bypass

RESULT INTERPRETATION

- vulnerable: true + confidence > 0.8: likely real, report it
- vulnerable: true + confidence < 0.5: flag as uncertain, needs manual verification
- vulnerable: false: move on, don't retest same tool + endpoint + params
- Multiple findings on one endpoint: weak input validation, test everything
- Check next_steps in scanner output -- they suggest follow-up actions

EXECUTION
- run_scanner_batch for independent tests on different endpoints
- Sequential when one result informs the next (crawl -> test endpoints; auth_test -> use token)
- WAF blocks (403 with security headers): report and move on
- Start 2-3 parallel tasks, increase if target handles it
- Never re-run same scanner on same endpoint with same parameters
```

**Key changes from current:**
1. NEW: endpoint type awareness (JSON vs HTML vs upload vs auth)
2. NEW: parameter name heuristics
3. NEW: confidence-based result interpretation
4. Removed redundant tool listing and error handling verbosity

---

### 1d. target.txt -- classification-first rewrite

File: `agent/packages/numasec/src/command/template/target.txt`
Current: 13 lines (rigid flow)
Target: ~20 lines (adds classification + recommendation)

```
You are setting up the engagement scope for a penetration test.

Target: $1

1. Call create_session to initialize the pentest session.
2. Probe the target with http_request (GET to $1). Examine: status code, Server header, X-Powered-By, Content-Type, Set-Cookie, response body structure.
3. Run recon with checks="ports,tech" for port scanning, service detection, technology fingerprinting.
4. Run crawl to discover endpoints, forms, JavaScript files, and API routes.

Now classify the target:
- Application type: REST API, SPA with API backend, server-rendered, or hybrid?
- Authentication: JWT, session cookies, API keys, OAuth, or none visible?
- Database signals: numeric IDs (SQL), ObjectIDs (NoSQL), search params (injection surface)?
- Attack surface: which discovered endpoints accept user input?

Present your classification and recommended testing strategy:
- Technologies and frameworks detected
- Total endpoints, highlighting those accepting user input
- 3-5 highest-priority tests and WHY (based on what you observed)
- Immediate red flags: known CVEs, exposed services, debug endpoints

Ask the user how to proceed before running any vulnerability scanners.
```

**Key changes from current:**
1. NEW: classification step (app type, auth, DB, surface)
2. NEW: reasoned recommendations ("3-5 tests and WHY")
3. Maintained safety: still asks user before active testing

---

## Phase 2: Tool Intelligence (Python code changes, compounds Phase 1 impact)

### 2a. Tool descriptions -- add "when to use" guidance

File: `numasec/tools/__init__.py`

Changes to description strings (add 1-2 sentences each):

| Tool | Add to description |
|------|-------------------|
| injection_test | "Most effective on endpoints accepting user input in query params or request body. Key signals: search parameters, numeric IDs, form submissions to API backends." |
| xss_test | "Most effective on endpoints returning HTML that reflect user input. Low value on pure JSON API responses." |
| access_control_test | "IDOR most effective on endpoints with sequential numeric IDs. CSRF only matters on state-changing operations (POST/PUT/DELETE)." |
| ssrf_test | "Most effective on endpoints with URL, redirect, callback, or webhook parameters." |
| path_test | "LFI effective on endpoints with file/path/template params. XXE requires XML input. Open redirect on redirect/next/url params." |
| upload_test | "Successful upload bypass can lead to remote code execution -- high severity finding." |
| race_test | "Most effective on state-changing endpoints: coupon redemption, balance transfers, voting, account creation." |

### 2b. Crawl output enrichment -- target_summary

File: `numasec/scanners/crawler.py` (CrawlResult or post-processing)

Add a `target_summary` field to crawl output dict:

```python
"target_summary": {
    "application_type": "spa_with_api" | "traditional" | "api_only" | "hybrid",
    "total_endpoints": int,
    "endpoints_with_params": int,
    "has_file_upload": bool,
    "has_auth_forms": bool,
    "api_indicators": ["url1", "url2"],  # endpoints matching /api/, /rest/, /graphql
}
```

Logic: classify based on ratio of JS files to HTML forms, presence of /api/ paths, etc. Data already available from crawl -- just needs synthesis.

### 2c. Recon output enrichment -- target_profile

File: `numasec/tools/composite_recon.py`

Add a `target_profile` synthesis at the end:

```python
"target_profile": {
    "probable_database": "MySQL" | "PostgreSQL" | "MongoDB" | None,  # from port 3306/5432/27017
    "web_server": "nginx" | "Apache" | None,  # from service banner
    "technologies": ["Express", "React"],  # from tech fingerprint
    "total_open_ports": int,
    "critical_cves": int,  # count of critical CVEs found
    "has_known_exploits": bool,  # any CVE with exploit_available=true
}
```

Logic: map port numbers to DB types, extract product names from banners, count CVEs. All data already in the recon result dict.

### 2d. SQLi output enrichment -- injection_context

File: `numasec/scanners/sqli_tester.py`

Add to each vulnerability dict:

```python
"injection_context": {
    "is_blind": bool,  # true for boolean_blind, time_blind
    "data_extractable": bool,  # true for error_based, union_based
    "database_confirmed": bool,  # true if DBMS was identified
}
```

3 booleans derived from existing technique + dbms fields.

### 2e. XSS output enrichment -- reflection_context

File: `numasec/scanners/xss_tester.py`

Add to each vulnerability dict:

```python
"reflection_context": {
    "encoding_bypassed": bool,  # true if payload reflected without encoding
    "csp_present": bool,  # true if Content-Security-Policy header exists
}
```

2 booleans. CSP is checkable from response headers already available.

---

## Phase 3: Validation

1. `ruff check numasec/` -- lint Python changes
2. `ruff format --check numasec/` -- format check
3. `mypy numasec/` -- type check Python changes
4. `pytest tests/ -m "not slow and not benchmark and not integration"` -- no regressions
5. `cd agent && bun typecheck` -- .txt changes don't break TUI
6. Before implementing Phase 2: check for exact-match assertions in tests that would break with new fields

---

## What this plan does NOT address

- **Auto-save bypass**: tool_bridge.py saves findings before the agent reasons about them. Deferred per user request.
- **Fine-tuned model**: prompts work across 16+ providers but a fine-tuned model would be even better.
- **Marketing/distribution**: this is the technical foundation. Virality comes from the product being undeniably better.
- **New scanners**: infrastructure is solid. Intelligence is the bottleneck.
- **TUI changes**: no UI modifications needed for this plan.

## Expected outcomes

After implementation:
1. Agent classifies targets before testing (no more XSS on JSON APIs)
2. Agent adapts priority based on what it observes (JWT app -> auth_test first)
3. Agent chains findings (SQLi found -> test same endpoint for other vulns)
4. Agent goes deep on promising endpoints before going wide
5. Tool output gives the LLM classification context it can't currently get
6. Tool descriptions guide better tool selection

The acid test: re-run Juice Shop pentest. The agent should test /rest/products/search?q= for BOTH SQLi AND XSS, not test XSS on the SPA route.
