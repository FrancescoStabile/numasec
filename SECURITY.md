# Security Policy

## 🔒 Responsible Disclosure

NumaSec is a penetration testing tool. Security vulnerabilities in NumaSec could enable:
- Unauthorized testing of targets
- Bypass of safety controls
- Data exposure from sessions

---

## 📬 Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, email: **francesco.stabile.dev@gmail.com**

Or create a private GitHub Security Advisory:
https://github.com/FrancescoStabile/numasec/security/advisories/new

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

**Response Time:**
- Initial response: 48 hours
- Patch for critical issues: 7 days

---

## 🛡️ Security Model

### Architecture

```
┌─────────────────────────────────────────┐
│  YOUR MACHINE (Trusted)                 │
│  - API keys                             │
│  - Session data (~/.numasec/)           │
└─────────────────────────────────────────┘
              ↕ NumaSec
┌─────────────────────────────────────────┐
│  LLM PROVIDERS (Semi-Trusted)           │
│  - DeepSeek, Claude, OpenAI             │
│  - Your prompts sent to them            │
└─────────────────────────────────────────┘
              ↕ HTTP/HTTPS
┌─────────────────────────────────────────┐
│  TARGETS (Untrusted)                    │
│  - Systems you're testing               │
│  - Scan results (may be malicious)      │
└─────────────────────────────────────────┘
```

### Mitigations

| Risk | Mitigation |
|------|------------|
| Command injection | Uses `subprocess.exec()` with arg lists, not shell |
| Path traversal | File ops restricted to CWD and ~/.numasec |
| API key leakage | Auto-redacted from logs |
| LLM prompt injection | Inherent LLM limitation, user review required |

### Accepted Risks

1. **Shell execution** - Core functionality, commands are logged
2. **LLM prompt injection** - Inherent to all LLM tools
3. **API keys in env vars** - Standard practice (like aws-cli, git)

---

## ⚖️ Legal Notice

### Authorized Use Only

✅ **Legal:**
- Your own systems
- Bug bounty programs (with authorization)
- CTF platforms (HackTheBox, DVWA, etc.)
- Authorized penetration tests

❌ **Illegal:**
- Systems without authorization
- Production systems without approval
- Government/critical infrastructure (unless authorized)

### Liability

NumaSec is provided "AS IS" under MIT License.

**You are responsible for:**
- Obtaining authorization before testing
- Compliance with local laws (CFAA, Computer Misuse Act, etc.)
- Consequences of misuse

---

## 🔄 Updates

```bash
# Always update before engagements
pip install --upgrade numasec
```

---

## 📊 Security Status

| Item | Status |
|------|--------|
| Dependencies | ✅ Minimal (10 packages) |
| Code audit | ✅ ~6k lines, auditable |
| API key handling | ✅ Auto-redacted |
| File access | ✅ Restricted paths |

---

**Last Updated:** February 5, 2026
