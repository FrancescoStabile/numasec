---
name: ptes-methodology
description: Complete PTES 5-phase penetration testing methodology with tool mappings
---

# PTES Penetration Testing Methodology

## Phase 1: Reconnaissance

**Objective**: Map the attack surface — ports, services, technologies, endpoints.

### Steps
1. **Port Scanning**: `recon` with default ports (top 1000) or full range
2. **Service Detection**: `recon` with `service_detection: true` — identifies versions
3. **Technology Fingerprinting**: `crawl` captures `X-Powered-By`, `Server` headers, meta tags
4. **Endpoint Discovery**: `crawl` + `dir_fuzz` — find hidden paths, admin panels, API routes
5. **JavaScript Analysis**: `js_analyze` — extract hardcoded secrets, API endpoints, sensitive comments
6. **OpenAPI Import**: If `/openapi.json` or `/swagger.json` exists, `crawl` auto-imports it

### Decision Point
After recon, assess:
- How many endpoints? → Narrow scope if > 200
- Any known CVEs? → Prioritize those
- Authentication required? → Get creds before vuln testing
- WAF detected? → Enable evasion in scanner params

## Phase 2: Discovery

**Objective**: Enumerate all testable inputs — forms, parameters, headers, cookies.

### Steps
1. **Deep Crawl**: `crawl` with `depth: 3` and `follow_redirects: true`
2. **Directory Fuzzing**: `dir_fuzz` with wordlist appropriate to technology stack
3. **Parameter Discovery**: Look at crawl results for query params, form fields, JSON bodies
4. **Authentication Endpoints**: Identify login, registration, password reset, OAuth flows
5. **API Documentation**: Check for GraphQL introspection, Swagger UI, API docs

## Phase 3: Vulnerability Assessment

**Objective**: Test for vulnerabilities across OWASP Top 10 categories.

### Systematic Testing Order
1. **Injection** (A03): `injection_test` on all input parameters
2. **XSS** (A03): `xss_test` on all reflected/stored inputs
3. **Broken Auth** (A07): `auth_test` for JWT, OAuth, session management
4. **Access Control** (A01): `access_control_test` for IDOR, privilege escalation
5. **SSRF** (A10): `ssrf_test` on URL parameters, file upload, webhooks
6. **Path Traversal** (A01): `path_test` on file parameters
7. **Security Misconfig** (A05): Check headers, CORS, default creds via `http_request`

### For Each Vulnerability Found
1. Confirm it's not a false positive
2. `save_finding` with full evidence (request, response, payload)
3. Assess exploitability and impact
4. Check for related vulnerabilities (attack chains)

## Phase 4: Exploitation (Controlled)

**Objective**: Confirm vulnerabilities are exploitable, demonstrate impact.

### Rules
- ALWAYS ask user before destructive payloads
- Document every exploitation step
- Use `kb_search` for exploitation techniques per vulnerability class
- Chain findings when possible (e.g., XSS → Session Hijack → Admin Access)

### Common Chains
- SQL Injection → Data Exfiltration → Credential Recovery
- SSRF → Internal Service Access → Cloud Metadata
- XSS → Cookie Theft → Account Takeover
- IDOR → Data Exposure → Privilege Escalation

## Phase 5: Reporting

**Objective**: Professional report with evidence, severity, and remediation.

### Steps
1. `/findings` — Review all findings
2. `/coverage` — Check OWASP coverage gaps
3. Eliminate false positives with @analyst
4. `/report markdown` or `/report html` — Generate the report
5. Review and refine with the user

### Report Quality Checklist
- [ ] Every finding has: title, severity, evidence, remediation
- [ ] CWE IDs are assigned
- [ ] CVSS scores are calculated
- [ ] OWASP categories are mapped
- [ ] Attack chains are documented
- [ ] Executive summary is actionable
