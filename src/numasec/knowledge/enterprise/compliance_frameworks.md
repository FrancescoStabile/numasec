# Compliance & Security Frameworks - Enterprise Guide

## PCI DSS (Payment Card Industry Data Security Standard)

### Requirements Overview
1. **Build and maintain secure networks**
2. **Protect cardholder data**
3. **Maintain vulnerability management program**
4. **Implement strong access control**
5. **Monitor and test networks**
6. **Maintain information security policy**

### Common PCI DSS Findings in Pentests

#### Requirement 2: Default Passwords
```bash
# Test for default credentials
admin:admin
root:password
sa:sa
```
**Finding:** Default credentials on network devices violates PCI DSS 2.1

#### Requirement 3: Cardholder Data Encryption
```sql
-- Detect unencrypted credit cards in DB
SELECT card_number FROM payments WHERE card_number LIKE '4%';
```
**Finding:** Credit card numbers stored in plaintext violates PCI DSS 3.4

#### Requirement 6: Security Vulnerabilities
- **SQL Injection** → PCI DSS 6.5.1
- **XSS** → PCI DSS 6.5.7
- **Broken Authentication** → PCI DSS 6.5.10
- **Insecure Cryptography** → PCI DSS 6.5.3

#### Requirement 8: Access Control
```bash
# Weak password policy test
passwords = ["123456", "password", "qwerty"]
```
**Finding:** Weak password policy violates PCI DSS 8.2.3

#### Requirement 10: Logging
**Finding:** Missing audit logs for admin actions violates PCI DSS 10.2.2

---

## HIPAA (Health Insurance Portability and Accountability Act)

### Security Rule Requirements

#### Administrative Safeguards
- **Risk Analysis** (§164.308(a)(1)(ii)(A))
- **Workforce Security** (§164.308(a)(3))
- **Information Access Management** (§164.308(a)(4))

#### Physical Safeguards
- **Facility Access Controls** (§164.310(a)(1))
- **Workstation Security** (§164.310(c))

#### Technical Safeguards
- **Access Control** (§164.312(a)(1))
- **Audit Controls** (§164.312(b))
- **Integrity** (§164.312(c)(1))
- **Transmission Security** (§164.312(e)(1))

### Common HIPAA Violations in Security Assessments

#### PHI (Protected Health Information) Exposure
```bash
# Publicly accessible patient data
curl https://hospital.com/patients/123.json
→ Returns: {"name":"John Doe","ssn":"123-45-6789","diagnosis":"..."}
```
**Violation:** §164.312(a)(1) - Access Control, §164.312(e)(1) - Transmission Security

#### Insufficient Encryption
```bash
# Patient portal using HTTP (not HTTPS)
http://portal.hospital.com/login
```
**Violation:** §164.312(e)(1) - Transmission Security (TLS required)

#### Lack of Audit Logs
**Violation:** §164.312(b) - Audit Controls (must log PHI access)

---

## GDPR (General Data Protection Regulation)

### Key Principles (Article 5)
1. **Lawfulness, fairness, transparency**
2. **Purpose limitation**
3. **Data minimization**
4. **Accuracy**
5. **Storage limitation**
6. **Integrity and confidentiality**
7. **Accountability**

### Security Testing Focus Areas

#### Article 32: Security of Processing
```markdown
Technical measures required:
- Pseudonymization and encryption of personal data
- Ability to ensure ongoing confidentiality, integrity, availability
- Ability to restore availability after incident
- Regular testing and evaluation of security measures
```

#### Common GDPR Findings

**Finding 1: Data Breach - No Encryption**
```sql
SELECT email, password FROM users;
→ Passwords stored as MD5 hashes (weak)
```
**Impact:** Article 32 violation (inappropriate security measures)

**Finding 2: Excessive Data Retention**
```bash
# User deleted account in 2020, data still exists in 2024
DELETE FROM users WHERE id=123;
→ Data still in audit_logs, backups, analytics DBs
```
**Impact:** Article 5(e) violation (storage limitation)

**Finding 3: Third-Party Data Exposure**
```html
<!-- Google Analytics tracking personal data -->
<script>
  gtag('event', 'purchase', {
    'user_email': 'john@example.com',  // PII sent to Google!
    'user_id': '12345'
  });
</script>
```
**Impact:** Article 44 violation (international data transfer without safeguards)

#### Data Subject Rights Testing
- **Right to Access (Article 15):** Can users export their data?
- **Right to Erasure (Article 17):** Does account deletion truly delete data?
- **Right to Rectification (Article 16):** Can users correct their data?

---

## SOC 2 (System and Organization Controls)

### Trust Service Criteria

#### Security (Mandatory)
- **CC6.1:** Logical/physical access controls
- **CC6.6:** Encryption of data at rest and in transit
- **CC6.7:** Protection against malicious software
- **CC7.2:** Detection of security events

#### Availability (Optional)
- **A1.2:** System monitoring and incident response
- **A1.3:** Backup and recovery procedures

#### Confidentiality (Optional)
- **C1.1:** Encryption and access restrictions for confidential data

### Common SOC 2 Audit Findings

#### CC6.1: Weak Access Controls
```bash
# IDOR vulnerability allowing data access
GET /api/customers/123 → User A's data
GET /api/customers/124 → User B's data (unauthorized!)
```
**Finding:** Insufficient logical access controls

#### CC6.6: Unencrypted Data
```bash
# Check for TLS
curl -I https://app.company.com
→ Protocol: HTTP/1.1 (not HTTPS)
```
**Finding:** Data not encrypted in transit

#### CC7.2: Missing Security Monitoring
**Finding:** No intrusion detection system, no SIEM logs

---

## ISO 27001

### Annex A Controls (Selected)

#### A.9: Access Control
- **A.9.2.1:** User registration and deregistration
- **A.9.4.1:** Information access restriction

#### A.12: Operations Security
- **A.12.6.1:** Management of technical vulnerabilities
  → **Action:** Vulnerability scanning, patch management

#### A.14: System Acquisition, Development & Maintenance
- **A.14.2.1:** Secure development policy
- **A.14.2.5:** Secure system engineering principles

### Security Testing Alignment
| ISO Control | Test Focus |
|-------------|------------|
| A.9.4.1     | Test for IDOR, broken access control |
| A.12.6.1    | Scan for outdated components (A06:2021) |
| A.14.2.1    | Check for SQL injection, XSS (dev practices) |
| A.18.1.5    | Validate data protection regulations (GDPR) |

---

## NIST Cybersecurity Framework (CSF)

### Core Functions
1. **Identify:** Asset management, risk assessment
2. **Protect:** Access control, data security, training
3. **Detect:** Anomaly detection, security monitoring
4. **Respond:** Incident response planning
5. **Recover:** Recovery planning, improvements

### Pentest Mapping to NIST CSF

#### Identify (ID)
- **ID.AM-2:** Software platforms and applications inventoried
  → **Test:** Discover all web apps, APIs, subdomains

#### Protect (PR)
- **PR.AC-1:** Identities and credentials managed
  → **Test:** Default credentials, weak passwords
- **PR.DS-1:** Data-at-rest is protected
  → **Test:** Check for unencrypted database backups

#### Detect (DE)
- **DE.CM-1:** Network monitored
  → **Test:** Check if WAF/IDS detects SQL injection attempts

#### Respond (RS)
- **RS.AN-1:** Notifications from detection systems investigated
  → **Test:** Trigger alerts, verify incident response

---

## CIS Controls (v8)

### Top 5 Critical Controls

#### 1. Inventory and Control of Enterprise Assets
**Test:** Discover unauthorized shadow IT (unapproved cloud services)

#### 2. Inventory and Control of Software Assets
**Test:** Scan for vulnerable software versions
```bash
nmap -sV target.com
→ Apache/2.2.8 (vulnerable to CVE-2017-15715)
```

#### 3. Data Protection
**Test:** Check for unencrypted data transmission (HTTP vs HTTPS)

#### 4. Secure Configuration of Enterprise Assets
**Test:** Default credentials, unnecessary services enabled

#### 5. Account Management
**Test:** Weak passwords, lack of MFA, privilege escalation

---

## Compliance Mapping Table

| Finding | PCI DSS | HIPAA | GDPR | SOC 2 | ISO 27001 |
|---------|---------|-------|------|-------|-----------|
| SQL Injection | 6.5.1 | §164.312(c) | Art. 32 | CC6.1 | A.14.2.1 |
| Weak Passwords | 8.2.3 | §164.308(a)(5) | Art. 32 | CC6.1 | A.9.2.1 |
| Unencrypted Data | 3.4 | §164.312(e)(1) | Art. 32 | CC6.6 | A.10.1.1 |
| Missing Logs | 10.2.2 | §164.312(b) | Art. 32 | CC7.2 | A.12.4.1 |
| IDOR | 6.5.8 | §164.312(a)(1) | Art. 32 | CC6.1 | A.9.4.1 |

---

## Reporting Compliance Findings

### Template for Compliance-Aware Reports

```markdown
## Finding: SQL Injection in Login Form

**Severity:** CRITICAL

**Description:**
The login form at /auth/login is vulnerable to SQL injection.

**Compliance Impact:**
- **PCI DSS 6.5.1:** Injection flaws not addressed
- **HIPAA §164.312(c)(1):** Integrity controls insufficient
- **GDPR Article 32:** Inadequate technical security measures
- **SOC 2 CC6.1:** Weak logical access controls
- **ISO 27001 A.14.2.1:** Secure development practices not followed

**Recommendation:**
1. Use parameterized queries/prepared statements
2. Implement input validation
3. Deploy WAF with SQL injection rules
4. Conduct code review of all database queries

**Regulatory Risk:**
- PCI DSS: Potential fine + loss of card processing
- HIPAA: Up to $50,000 per violation
- GDPR: Up to 4% of annual global revenue
```

---

## Regulatory Penalties (for context)

| Regulation | Max Penalty |
|------------|-------------|
| PCI DSS | $5,000 - $100,000/month + card ban |
| HIPAA | $50,000 per violation (up to $1.5M/year) |
| GDPR | €20M or 4% global revenue (whichever higher) |
| SOC 2 | Loss of certification, customer trust |

---

## References
- PCI DSS v4.0: https://www.pcisecuritystandards.org/
- HIPAA Security Rule: https://www.hhs.gov/hipaa/
- GDPR Official Text: https://gdpr-info.eu/
- NIST CSF: https://www.nist.gov/cyberframework
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
- CIS Controls: https://www.cisecurity.org/controls/
