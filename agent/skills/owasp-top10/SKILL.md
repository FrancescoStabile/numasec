---
name: owasp-top10
description: OWASP Top 10 2021 testing checklist with tool mappings and detection strategies
---

# OWASP Top 10 (2021) Testing Checklist

## A01: Broken Access Control

### What to Test
- Horizontal privilege escalation (IDOR): access other users' resources
- Vertical privilege escalation: access admin functions as regular user
- Missing function-level access controls on API endpoints
- Metadata manipulation (JWT claims, cookies, hidden fields)
- CORS misconfiguration allowing unauthorized cross-origin access
- Directory traversal / path traversal

### Tools
- `access_control_test` — IDOR detection, privilege escalation patterns
- `path_test` — directory traversal (../etc/passwd, etc.)
- `http_request` — manual testing with modified auth tokens
- `auth_test` — JWT claim manipulation

### Detection Patterns
- 200 OK when accessing another user's resource
- Same response for different privilege levels
- API endpoints accessible without authentication
- Predictable resource IDs (sequential integers)

## A02: Cryptographic Failures

### What to Test
- Sensitive data transmitted over HTTP (not HTTPS)
- Weak TLS configuration
- Passwords stored in plaintext or weak hashes
- Missing encryption for PII, financial data
- Hardcoded secrets in JavaScript

### Tools
- `js_analyze` — find hardcoded API keys, tokens, passwords
- `http_request` — check for HTTP→HTTPS redirects, HSTS headers
- `recon` — detect TLS version and cipher suite

## A03: Injection

### What to Test
- SQL injection (error-based, blind, UNION, time-based)
- NoSQL injection (MongoDB operators, JSON injection)
- Command injection (OS commands via user input)
- SSTI (Server-Side Template Injection)
- LDAP injection
- XPath injection
- Header injection (Host, X-Forwarded-For)

### Tools
- `injection_test` — comprehensive injection testing (SQLi, NoSQLi, CMDi, SSTI)
- `xss_test` — XSS (reflected, stored, DOM-based)
- `http_request` — targeted manual payloads

### Key Parameters to Test
- URL query parameters
- POST body (form data, JSON)
- HTTP headers (Cookie, Referer, User-Agent)
- File upload filenames
- REST path segments

## A04: Insecure Design

### What to Test
- Business logic flaws (price manipulation, rate limit bypass)
- Missing rate limiting on auth endpoints
- Insufficient anti-automation
- Lack of input validation on business constraints

### Tools
- `auth_test` with credential spray — test rate limiting
- `http_request` — replay and modify business logic requests
- `browser` — test multi-step workflows

## A05: Security Misconfiguration

### What to Test
- Default credentials on admin panels
- Unnecessary HTTP methods enabled (PUT, DELETE, TRACE)
- Directory listing enabled
- Verbose error messages exposing stack traces
- Missing security headers
- Unnecessary services/ports open

### Tools
- `recon` — open ports and service versions
- `dir_fuzz` — find admin panels, config files, backups
- `http_request` — check headers (X-Frame-Options, CSP, etc.)
- `auth_test` — default credential testing
- `crawl` — detect error pages with stack traces

### Security Headers Checklist
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy`
- `Permissions-Policy`

## A06: Vulnerable and Outdated Components

### What to Test
- Server software versions with known CVEs
- JavaScript library versions (jQuery, Angular, React)
- Framework versions exposed in headers/responses

### Tools
- `recon` — service version detection + CVE enrichment
- `js_analyze` — detect JS library versions
- `crawl` — technology fingerprinting
- `kb_search` — look up CVE details and exploits

## A07: Identification and Authentication Failures

### What to Test
- Brute force / credential stuffing resistance
- Weak password policy
- Session fixation
- JWT vulnerabilities (none algorithm, weak secret, missing expiry)
- OAuth misconfiguration (open redirects, token leakage)
- Multi-factor authentication bypass
- Password reset flaws

### Tools
- `auth_test` — comprehensive auth testing (JWT, OAuth, spray)
- `http_request` — session manipulation
- `browser` — test OAuth flows, MFA bypass

## A08: Software and Data Integrity Failures

### What to Test
- Deserialization vulnerabilities
- CI/CD pipeline security
- Missing integrity checks on downloads/updates
- Third-party dependency trust

### Tools
- `injection_test` — deserialization payloads (Java, PHP, Python)
- `js_analyze` — detect unsafe deserialization patterns

## A09: Security Logging and Monitoring Failures

### What to Test
- Login failures not logged
- High-value transactions not logged
- Logs accessible to unauthorized users
- No alerting on suspicious activity

### Tools
- `http_request` — generate events and check for detection
- `dir_fuzz` — find exposed log files

## A10: Server-Side Request Forgery (SSRF)

### What to Test
- URL parameters fetching remote resources
- File import/export functionality
- Webhook URLs
- PDF generators, screenshot services
- Cloud metadata access (169.254.169.254)

### Tools
- `ssrf_test` — comprehensive SSRF testing with OOB detection
- `oob` — out-of-band callback detection
- `http_request` — manual SSRF payloads targeting cloud metadata
