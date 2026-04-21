---
name: passive-osint
description: Passive reconnaissance against a target without sending traffic that could alert it. Load when the engagement starts, when you only know a domain/email/username, when scope is unclear, or when you need historical surface area. Covers subdomain enumeration (crt.sh, subfinder), historical archives (wayback), DNS posture (dnsrecon), email & breach surface (theharvester, holehe), and username reuse (sherlock). All commands are free and key-less.
---

# Passive OSINT kit

**Rule of engagement.** Passive OSINT means zero direct traffic to the target's infrastructure. Every command here either hits public archives (crt.sh, wayback, PassiveDNS), third-party directories (theharvester, sherlock, holehe), or local DNS (which any resolver anywhere in the world is allowed to answer). Never run active scanners from this skill.

**Output contract.** Every finding or artifact is a candidate observation. After running a command and triaging the output, write the interesting rows to `core/observation/store` via the normal mechanism (or, if you are the user, copy into an operation's `observations.jsonl`). Always include severity and confidence.

## When to load

| Situation | Why |
|---|---|
| First turn of a new pentest / bughunt / osint operation | Always start here — cheapest recon, highest signal |
| Scope says `*.example.com` and you don't know the subdomains | crt.sh + subfinder resolves "how big is the attack surface?" |
| Target is an org name, not an asset | theharvester + sherlock + holehe tell you humans to recon |
| Re-engagement after months | wayback shows what changed |

## Toolbox

### 1. crt.sh — Certificate transparency (HTTP, key-less)

Certificate Transparency logs publish every TLS cert issued. Querying them reveals subdomains without asking the target's DNS.

```bash
# All certs for a domain (JSON)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Filter out wildcards, split SAN entries on newlines
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' \
  | tr '\n' '\n' | awk 'NF' | sort -u | grep -v '^\*'
```

**Interpretation:** every unique hostname is a candidate subdomain. Feed into `dnsrecon` or `host` to check DNS resolution.

### 2. subfinder — Aggregator for passive subdomain sources

`subfinder` queries ~30 public data sources (VirusTotal, AlienVault OTX, Shodan's free endpoints, HackerTarget, etc.) with no keys required for the built-in defaults.

```bash
# Install if missing: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
subfinder -d example.com -silent -all
subfinder -d example.com -silent -all -o subs.txt
```

**Pairing:** `cat subs.txt | httpx -silent` (active, only after scope allows) to check which resolve & serve HTTP.

### 3. wayback — Historical URL surface

The Internet Archive indexes old content. Find deleted endpoints, forgotten admin panels, staging URLs.

```bash
# Raw list of known URLs (Common Crawl / wayback index)
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/*&output=text&fl=original&collapse=urlkey" | sort -u

# Filter interesting file types
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/*&output=text&fl=original&collapse=urlkey" \
  | grep -iE '\.(git|env|bak|config|yaml|log|sql|pem|key)$'
```

**Interpretation:** any URL pointing to `/admin`, `/.git/`, `/config.yaml`, backups, or legacy APIs is an observation candidate (severity `medium`, confidence `low` until confirmed).

### 4. dnsrecon — DNS posture mapping

```bash
# Install: apt install dnsrecon  OR  pip install dnsrecon
dnsrecon -d example.com -t std           # A, AAAA, MX, NS, SOA, TXT
dnsrecon -d example.com -t brt -D ~/wordlists/subdomains-top1million-5000.txt  # brute-force (active — scope-gate this)
dnsrecon -d example.com -t zonewalk       # DNSSEC zone walking where supported
```

**Severity hints.** SPF `?all` or missing → spoofing risk (`low-medium`). Exposed AXFR → `high`. Wildcard A record → recon noise; lower confidence on brute-force results.

### 5. theHarvester — Emails, names, hosts from public sources

```bash
# Install: pip install theHarvester  (no keys required for default engines)
theHarvester -d example.com -b duckduckgo,bing,crtsh,anubis,hackertarget -f harvest.xml
```

**Feed:** emails into `holehe`, usernames into `sherlock`, hosts into the subdomain list.

### 6. holehe — Email-to-service existence

For every email harvested, check which services that email is registered on.

```bash
# Install: pip install holehe
holehe victim@example.com --no-color --only-used
```

**Ethics.** Holehe doesn't confirm credentials — only that an address is known. Use for social-engineering scope mapping.

### 7. sherlock — Username reuse

```bash
# Install: pip install sherlock-project
sherlock jdoe --timeout 5 --print-found
```

**Output:** every hit is a public profile, a potential pretext channel, or a leak root.

## Standard passive-recon opening

When starting a new engagement with only `example.com`, run in order:

1. `crt.sh` → raw subdomain list.
2. `subfinder` → augment with other passive sources.
3. Deduplicate → `candidates.txt`.
4. `wayback` over `example.com/*` → historical URLs.
5. `dnsrecon -t std` → DNS posture for the apex.
6. `theHarvester` for emails/names.
7. For each interesting email: `holehe`. For each username: `sherlock`.
8. Summarize into 3-7 observations with severity/confidence.
9. Present the operator a prioritized list of "what we would do if active recon were in scope".

## What this skill does NOT do

- No active scanning, no port scans, no HTTP fuzzing — those live in `skills/surface-recon/` (if loaded) or the `scanner` tool.
- No credential checks (not HIBP, not breach lookups that require a key).
- No DNS zone writes. Read only.

## Escalation

After passive OSINT completes, the natural next steps are (all scope-gated):

- Active DNS resolution + HTTP enumeration → `scanner` tool (product `native-crawl`, `native-portscan`).
- Directory fuzzing on the confirmed alive hosts → `scanner` tool (product `ffuf`).
- Vulnerability scanning → `scanner` tool (product `nuclei`).
- Deeper application-layer work → `pentest` agent via `task` tool.
