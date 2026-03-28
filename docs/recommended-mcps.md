# Recommended MCP Servers for numasec

numasec is an MCP host — it can connect to external MCP servers to extend its capabilities. This guide lists security-relevant MCP servers that pair well with numasec's pentesting workflow.

## Quick Setup

Add MCP servers to your `~/.numasec/mcp.json` (or the project-level `.mcp.json`):

```json
{
  "mcpServers": {
    "numasec": {
      "command": "numasec",
      "args": ["mcp"]
    },
    "playwright": {
      "command": "npx",
      "args": ["@anthropic/mcp-playwright"]
    }
  }
}
```

---

## Browser & UI Testing

### Playwright MCP
**What:** Browser automation — navigate pages, fill forms, click buttons, take screenshots.
**Why:** Essential for testing stored XSS, complex auth flows, SPAs that require JavaScript rendering, and capturing visual evidence of vulnerabilities.
**Install:** `npm install -g @anthropic/mcp-playwright`
```json
{
  "playwright": {
    "command": "npx",
    "args": ["@anthropic/mcp-playwright"]
  }
}
```
**Use with numasec:** After finding a reflected XSS, use Playwright to demonstrate DOM-based exploitation. Capture screenshots for evidence.

---

## Database Access (Post-Exploitation)

### PostgreSQL MCP
**What:** Direct database access — run queries, inspect schemas, enumerate data.
**Why:** After confirming SQL injection, connect directly to verify data exposure scope.
**Install:** `npm install -g @anthropic/mcp-postgres`
```json
{
  "postgres": {
    "command": "npx",
    "args": ["@anthropic/mcp-postgres", "postgresql://user:pass@target:5432/db"]
  }
}
```

### MySQL MCP
**What:** MySQL/MariaDB database access.
**Why:** Same as PostgreSQL — post-SQLi verification and scope assessment.

### SQLite MCP
**What:** SQLite database file access.
**Why:** Many web apps use SQLite. After LFI or file upload vuln, inspect database files directly.

---

## Cloud Security

### AWS MCP
**What:** AWS API access — S3, IAM, EC2, Lambda inspection.
**Why:** After SSRF → cloud metadata extraction, verify the scope of cloud access. Check S3 bucket permissions, enumerate IAM roles.
**Workflow:** numasec finds SSRF → extracts AWS credentials → AWS MCP verifies what the credentials can access.

### GCP / Azure MCPs
**What:** Google Cloud and Azure API access.
**Why:** Same as AWS — post-SSRF cloud enumeration.

---

## Code Analysis

### Git MCP (GitHub)
**What:** Repository access — read files, search code, list PRs.
**Why:** The `review` agent can analyze source code for vulnerabilities without cloning the repo locally. Search for hardcoded secrets, insecure patterns, vulnerable dependencies.
```json
{
  "github": {
    "command": "npx",
    "args": ["@anthropic/mcp-github"]
  }
}
```

### Filesystem MCP
**What:** Read/write files on disk.
**Why:** Analyze downloaded source code, read configuration files, process scan output files.

---

## Vulnerability Scanning

### Nuclei (if wrapped as MCP)
**What:** Template-based vulnerability scanning with 10,000+ community templates.
**Why:** Complements numasec's native scanners with Nuclei's massive template library. numasec's AI decides WHEN to run which templates based on recon findings.
**Note:** numasec already has conditional `nuclei_scan` registration if nuclei is installed. An MCP wrapper would provide richer integration.

---

## Network & Infrastructure

### DNS MCP
**What:** DNS record lookup, zone transfer testing.
**Why:** Subdomain enumeration, DNS misconfiguration detection.

### Shodan MCP
**What:** Passive reconnaissance via Shodan API.
**Why:** numasec already has a built-in Shodan scanner, but an MCP wrapper could provide richer API access for the recon agent.

---

## Recommended Combinations

### Web Application Pentest
```
numasec (core) + Playwright (browser) + GitHub (code review)
```

### API Security Assessment
```
numasec (core) + PostgreSQL (post-exploitation) + AWS (cloud)
```

### Full-Scope Pentest
```
numasec (core) + Playwright (browser) + GitHub (code) + AWS (cloud) + PostgreSQL (database)
```

---

## Building Your Own Security MCP

numasec can consume any MCP server. To build a custom security tool as an MCP:

1. Use the [MCP SDK](https://github.com/modelcontextprotocol/sdk) (Python or TypeScript)
2. Expose your tool's functionality as MCP tools with clear JSON schemas
3. Return structured results that numasec's agents can reason about
4. Add it to your `.mcp.json` and numasec will auto-discover it

Example: wrapping a custom internal scanner, a proprietary WAF bypass tool, or a company-specific compliance checker.

---

## Security Considerations

When connecting MCP servers to numasec:
- **Scope:** Ensure external MCPs respect the same target scope as numasec
- **Credentials:** MCP servers may require API keys — store them in environment variables, not config files
- **Network:** Some MCPs make outbound requests — ensure they route through your proxy if configured (`NUMASEC_PROXY`)
- **Isolation:** Each MCP server runs as a separate process — a crash in one doesn't affect others
