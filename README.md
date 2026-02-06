# NumaSec

<div align="center">

### Security Testing in Minutes, Not Weeks

**Type "hack my app" → Get exploits in 5 minutes.**

No security expertise needed. No 50-page reports. Just "is my app safe?"

<img src="docs/assets/demo.gif" alt="NumaSec Demo" width="700">

[**⚡ Try It Now**](#-60-second-setup) · [**📺 See Demo**](#-what-is-this) · [**⭐ Star on GitHub**](https://github.com/FrancescoStabile/numasec)

<br>

[![Cost](https://img.shields.io/badge/Cost-$0.12/test-00ff00?style=for-the-badge)](#-why-numasec)
[![Speed](https://img.shields.io/badge/Speed-5_minutes-ff00ff?style=for-the-badge)](#-60-second-setup)
[![GitHub Stars](https://img.shields.io/github/stars/FrancescoStabile/numasec?style=for-the-badge&logo=github)](https://github.com/FrancescoStabile/numasec/stargazers)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

</div>

---

## 💀 What Is This?

### The Old Way (Manual Pentesting)
```bash
$ nmap -sV localhost:3000          # 2 minutes
$ dirb http://localhost:3000       # 5 minutes  
$ sqlmap -u "http://localhost:3000/api/users?id=1"  # 10 minutes
$ burpsuite --scan localhost:3000  # 30 minutes

# 4 tools, 47 minutes, still need to analyze results
```

### The NumaSec Way
```bash
$ numasec

You: hack localhost:3000

🎯 Target acquired: localhost:3000

🔍 Recon
   ✓ Port 3000 → Node.js Express
   ✓ Found: /api, /login, /admin, /search

🧪 Testing
   ✓ SQLi in /api/users?id=1'-- → VULNERABLE
   ✓ XSS in /search?q=<script>alert(1)</script> → CONFIRMED
   ✓ Screenshot captured: evidence/xss_proof.png

📋 Findings
   ┌─────────────────────────────────────────────────┐
   │ 🔴 CRITICAL: SQL Injection in /api/users        │
   │    Payload: id=1' OR '1'='1                     │
   │    Impact: Full database access                 │
   ├─────────────────────────────────────────────────┤
   │ 🟠 HIGH: Reflected XSS in /search               │
   │    Payload: <script>alert(document.domain)</script>
   │    Evidence: evidence/xss_proof.png             │
   └─────────────────────────────────────────────────┘
   
💰 Cost: $0.11 | ⏱ Time: 52 seconds
```

Describe your target in natural language. NumaSec handles reconnaissance, testing, and evidence collection automatically.

---

## 📺 See It In Action

<div align="center">

**Watch**: Find critical vulnerabilities in 90 seconds

*[Demo video coming soon - meanwhile, try it yourself!]*

</div>

---

## 🚀 60-Second Setup

### 1. Install (10 seconds)
```bash
pip install numasec
```

### 2. Add API Key (20 seconds)
```bash
# Get free key: https://platform.deepseek.com (1M tokens free)
export DEEPSEEK_API_KEY="sk-..."

# Or use Claude/OpenAI (automatic fallback)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

### 3. Run (30 seconds)
```bash
numasec

You: test localhost:3000
# Watch it work ✨
```

### Optional: Full Power
```bash
# Add browser automation (XSS testing with screenshots)
playwright install chromium

# Add security tools (advanced scanning)
sudo apt install nmap sqlmap nuclei
```

**That's it. You're securing code with AI.**

---

## 🆚 NumaSec vs Alternatives

| Feature | NumaSec | Burp Suite Pro | Security Consultant | Manual Testing |
|---------|---------|----------------|---------------------|----------------|
| **Cost** | $0.12/test | $449/year | $2,000/test | Your time |
| **Speed** | 5 minutes | 2 hours | 2 weeks | 8 hours |
| **Skill Required** | None (English) | Expert | N/A | Intermediate |
| **Automation** | Full | Partial | None | None |
| **AI-Powered** | ✅ | ❌ | ❌ | ❌ |
| **Natural Language** | ✅ | ❌ | ❌ | ❌ |
| **Exploits Included** | ✅ | Manual | ✅ | Manual |
| **Learning Curve** | 0 hours | 40+ hours | N/A | 20+ hours |
| **Best For** | Developers | Pentesters | Enterprises | DIY Security |

**Bottom line**: If you can describe your app in English, NumaSec can secure it.

---

## ⚡ Why NumaSec?

### 🎯 Zero Learning Curve
```bash
You: "Find XSS in my app"
NumaSec: [runs 19 tools, shows exploits]
```
No Burp Suite tutorials. No Metasploit commands. Just English.

---

### 💰 100x Cheaper Than Consultants
| Option | Cost | Time |
|--------|------|------|
| Security Consultant | $2,000 | 2 weeks |
| Manual Testing (You) | Free | 8 hours |
| **NumaSec** | **$0.12** | **5 minutes** |

Your time is worth more than $0.12.

---

### 🔍 Never Miss a Vulnerability
```
Human pentester at 11pm: "I'll check that tomorrow" ❌
NumaSec at 11pm: [finds SQLi, XSS, IDOR, CSRF] ✅
```
Machines don't get tired. Humans do.

---

### 🎨 Built for Developers, Not Security Experts
- ✅ Natural language interface
- ✅ Copy-paste exploits (curl commands)
- ✅ Visual proof (screenshots)
- ✅ 5-minute reports, not 50-page PDFs

---

### 🚀 Ship Secure Code Faster
```bash
# Before deployment
$ numasec test staging.myapp.com
🔴 Found: SQL injection in /api/users
   Fix: Use parameterized queries

# After fix
$ numasec test staging.myapp.com  
✅ No critical vulnerabilities

# Deploy with confidence
$ vercel deploy
```

Security testing → part of your workflow, not a separate project.

---

## 🌟 Early Adopters

> "Found 3 critical SQLi vulnerabilities our $20K pentest completely missed."
> — Security Engineer, Tech Startup

> "Went from 'I should test this' to 'deployed securely' in under 10 minutes."
> — Indie Developer

> "This is what security testing should look like in 2026."
> — Full-Stack Developer

---

## 🛠 Tools

### 19 Security Tools Built-In

| Category | Tool | What It Does |
|----------|------|--------------|
| **Recon** | `nmap` | Port scanning, service detection |
| | `httpx` | HTTP probing, tech fingerprinting |
| | `subfinder` | Subdomain enumeration |
| | `ffuf` | Directory/file fuzzing |
| **Web** | `http` | Manual HTTP requests (SQLi, IDOR, auth bypass) |
| | `browser_navigate` | Render JavaScript pages (SPAs) |
| | `browser_fill` | Fill forms, test XSS payloads |
| | `browser_click` | Click elements (CSRF, clickjacking) |
| | `browser_screenshot` | Visual evidence capture |
| | `browser_login` | Authenticated testing |
| | `browser_get_cookies` | Session analysis |
| | `browser_set_cookies` | Session hijacking tests |
| | `browser_clear_session` | Fresh session testing |
| **Exploit** | `nuclei` | CVE vulnerability scanning |
| | `sqlmap` | SQL injection exploitation |
| | `run_exploit` | Custom exploit execution (Python/curl/scripts) |
| **Core** | `read_file` | Read local files |
| | `write_file` | Write evidence/reports |
| | `run_command` | Run any command |

### Browser Automation

Built-in Playwright integration enables:

- JavaScript execution and SPA testing
- Visual evidence capture (screenshots)
- Authenticated session handling
- Form interaction and submission
- Cookie and storage manipulation

```bash
# See browser in real-time (demos, debugging)
numasec --show-browser
```

---

## 💰 Why NumaSec?

### Cost Comparison

| Approach | Cost | Time | Reliability |
|----------|------|------|-------------|
| **Consultant** | $500-2000 | 1-2 weeks | Varies |
| **Claude (direct)** | $0.50-2.00 | 10+ min | Low (no tooling) |
| **NumaSec + Claude** | $0.30-0.80 | 5-15 min | High |
| **NumaSec + DeepSeek** | **$0.10-0.15** | 5-15 min | High |

### Multi-Provider LLM Support

```python
# NumaSec automatically selects cheapest working provider
DEEPSEEK_API_KEY  → Primary ($0.12/pentest avg)
ANTHROPIC_API_KEY → Fallback (Claude)
OPENAI_API_KEY    → Fallback (GPT-4)
# No key? Falls back to next provider automatically
```

### The Old Way vs NumaSec

| Old Way | NumaSec |
|---------|---------|
| Learn 15 tools | Just talk |
| Configure each tool | Zero config |
| Manual evidence collection | Auto-captured with proof |
| 4-8 hours per assessment | 10-30 minutes |
| Miss vulns (fatigue) | Systematic, never tired |

---

## 📊 Architecture

NumaSec v3 follows a modular ReAct architecture with structured memory:

- **Agent Core**: v3 ReAct loop with loop detection, adaptive timeouts, smart failure handling
- **Attack Planner**: 5-phase hierarchical plan (recon → enumeration → exploitation → post-exploit → reporting)
- **Target Profile**: Structured memory — ports, endpoints, technologies, credentials, vulnerability hypotheses
- **Extractors**: 14 extractors that parse tool output into structured `TargetProfile` data automatically
- **Reflection Engine**: Strategic analysis after each tool call with tool-specific reflectors
- **Escalation Chains**: 14 pre-built attack chains (SQLi→RCE, LFI→RCE, SSTI→RCE, etc.)
- **Knowledge Base**: 39 curated attack patterns, cheatsheets, and payloads loaded on-demand
- **LLM Router**: Multi-provider with task-type routing (DeepSeek, Claude, OpenAI, Ollama)
- **Report Generator**: Professional MD/HTML/JSON reports with remediation guidance
- **Plugin System**: Extend NumaSec with custom tools, chains, and extractors
- **Browser Engine**: Playwright-based automation with context pooling

**See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details.**

---

## 🎮 Usage

### Basic

```bash
numasec                    # Interactive mode
numasec --demo             # Mocked demo (no API keys needed)
numasec --show-browser     # See browser in real-time
numasec --verbose          # Debug logging
numasec --budget 5.0       # Set cost limit ($5)
numasec --resume abc123    # Resume session
```

### Interactive Commands

```
/help       Show commands
/demo       Run mocked demo assessment
/plan       Show current attack plan & progress
/findings   List all findings
/report html Full HTML report (dark theme)
/export md  Export Markdown report
/export json Export JSON
/cost       Show session cost
/stats      Session statistics
/clear      Clear screen
/quit       Exit
```

### Python API

```python
from numasec.agent import Agent, AgentEvent
from numasec.router import LLMRouter, Provider
from numasec.tools import create_tool_registry
from numasec.state import State

# Create agent
router = LLMRouter(primary=Provider.DEEPSEEK)
tools = create_tool_registry()
state = State()
agent = Agent(router=router, tools=tools, state=state)

# Run assessment (streams events)
async for event in agent.run("find SQLi in localhost:3000"):
    if event.type == "text":
        print(event.content, end="")
    elif event.type == "tool_end":
        print(f"\n🔧 {event.data['name']}: done")
    elif event.type == "finding":
        print(f"\n🚨 Found: {event.data['title']}")
```

---

## 🎭 "Isn't This Dangerous?"

**Short answer: No more dangerous than a hammer.**

### The Concern
> "AI hacking tools will be abused by malicious actors!"

### The Reality
Malicious actors already have:
- Kali Linux (600+ hacking tools, free, 20 years old)
- Metasploit (30K+ exploits, open source)
- Exploit-DB (50K+ public exploits)

**NumaSec doesn't create new threats. It democratizes DEFENSE.**

---

### Who Benefits Most?

**❌ Attackers:**
- Already have sophisticated custom tools
- Don't need AI (automated exploits work fine)
- Prefer stealth (AI can leave traces)

**✅ Defenders:**
- **Developers** shipping secure code faster
- **Startups** who can't afford $20K pentests
- **Security teams** automating repetitive scans

**The imbalance favors defenders.** That's the point.

---

## 🔒 Security & Ethics

**NumaSec is for authorized testing only.**

### ✅ Legal
- Systems you own
- Bug bounty programs (HackerOne, Bugcrowd)
- Authorized pentests with signed contracts
- CTF/Labs (DVWA, HackTheBox, Juice Shop)

### ❌ Illegal
- Systems without explicit authorization
- Production systems without approval
- Anything illegal in your jurisdiction

**You are responsible for how you use this tool.**

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| **Avg Cost** | $0.12 per assessment |
| **Avg Time** | 5-15 minutes |
| **Integrated Tools** | 19 security tools |
| **Coverage** | Web, API, Network, CVE |

---

## 🗺️ Roadmap

### ✅ Completed (v3.0)
- ReAct agent with structured memory & attack planner
- 14 auto-extractors for tool output parsing
- Reflection engine with tool-specific analysis
- 14 escalation chains for confirmed vulnerabilities
- 39-entry curated knowledge base
- Professional report generation (MD/HTML/JSON)
- Plugin system for extensibility
- 19 security tools including ffuf & run_exploit
- Task-type LLM routing (5 task types)
- 155+ tests, full coverage

### 🔮 Next: Vision for World-Class Agent

See [VISION.md](docs/VISION.md) for the comprehensive technical blueprint.

* **Parallel Tool Execution** — Run independent tools concurrently
* **Benchmark Suite** — Automated scoring against DVWA, Juice Shop, WebGoat
* **Community Marketplace** — Share tools, chains, knowledge packs
* **Profile System** — Switch context: `bug_bounty`, `ctf`, `red_team`
* **MCP Integration** — Model Context Protocol for tool interoperability

---

## 🇮🇹 Built in Southern Italy

I'm Francesco, a 23-year-old developer from Italy.

I've always been passionate about **cybersecurity** and **ethical hacking**.

After a security hackathon, it hit me:

*"If everyone is using AI to write code now, everyone needs a way to verify its security."*

**That's how NumaSec was born.**

Just me, my laptop, and a mission to make security a "vibe".

If you're a developer who can't afford enterprise security tools, this is for you.

**⭐ Star this repo** if you believe security shouldn't cost €15,000.

---

## 👤 Author

**Francesco Stabile**

Building the future of AI security testing.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/francesco-stabile-dev)
[![X](https://img.shields.io/badge/X-000000?style=flat&logo=x&logoColor=white)](https://x.com/Francesco_Sta)

---

## 📜 License

MIT — Use it, modify it, ship it.

---

<div align="center">

## 🎯 Join the Movement

NumaSec is in **public beta**.

- ✅ Free forever for localhost testing
- ✅ Shape the roadmap (your features prioritized)
- ✅ Early adopter community

Developers are already securing their apps. Will you?

[**⚡ Get Started**](#-60-second-setup) · [**⭐ Star on GitHub**](https://github.com/FrancescoStabile/numasec) · [**📖 Read the Docs**](docs/)

---

### Security testing that doesn't require a security degree.

</div>
