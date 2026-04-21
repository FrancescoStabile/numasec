// Kind registry (v1 — in-repo).
//
// A Kind is a verticalized security work-mode. At v1 there is a strict 1:1
// mapping between Kind and primary Agent (security / pentest / appsec / osint
// / hacking). Future iterations can add more kinds, and eventually lift packs
// into external plugins (see docs/strategy).
//
// Kept intentionally small and pure — no I/O, no effect system — so it can
// be imported from any layer (CLI, TUI, server, SDK stubs) without cycles.

export type KindId = "security" | "pentest" | "appsec" | "osint" | "hacking"

export interface KindPack {
  id: KindId
  label: string
  short: string
  agent: string
  glyph: string
  accent: "primary" | "secondary" | "accent" | "warning" | "error" | "info" | "success"
  tagline: string
  placeholders: {
    normal: string[]
    shell: string[]
  }
  thinking: string[]
  deliverable: string
}

const PACKS: Record<KindId, KindPack> = {
  security: {
    id: "security",
    label: "Security Sidekick",
    short: "sec",
    agent: "security",
    glyph: "◈",
    accent: "info",
    tagline: "Jarvis on Kali — install, explain, analyze logs, anything ad-hoc",
    placeholders: {
      normal: [
        "install nuclei and run a quick scan on http://localhost",
        "explain SAML reflection attacks with one example",
        "tail this log and tell me what looks weird",
        "what's the latest CVE for nginx 1.18?",
      ],
      shell: ["apt install -y nuclei", "tail -n 200 /var/log/auth.log", "openssl s_client -connect host:443"],
    },
    thinking: [
      "grepping the docs",
      "man 1 man",
      "sudo think",
      "piping to brain",
      "diff-ing my memory",
      "querying the oracle",
    ],
    deliverable: "answer",
  },
  pentest: {
    id: "pentest",
    label: "Penetration Test",
    short: "pwn",
    agent: "pentest",
    glyph: "◆",
    accent: "error",
    tagline: "Authorized engagement — scope, findings, evidence, report",
    placeholders: {
      normal: [
        "Pentest http://localhost:3000",
        "Look for IDOR on /api/users/:id",
        "Chain SSRF with metadata exfil on this target",
      ],
      shell: ["nmap -sV target.local", "nuclei -u http://target", "sqlmap -u 'http://target?id=1'"],
    },
    thinking: [
      "cooking the payload",
      "tickling the firewall",
      "befriending the SIEM",
      "counting the privescs",
      "drawing the kill chain",
      "asking for admin nicely",
    ],
    deliverable: "pentest-report",
  },
  appsec: {
    id: "appsec",
    label: "Application Security Review",
    short: "asec",
    agent: "appsec",
    glyph: "❮❯",
    accent: "accent",
    tagline: "Read the code like a reviewer — bugs, sinks, fixes",
    placeholders: {
      normal: [
        "Review this repo for authz bugs",
        "Audit dependencies for known CVEs",
        "Find all sinks that reach user input",
      ],
      shell: ["semgrep --config=auto .", "npm audit --production", "git log -p -- src/auth"],
    },
    thinking: [
      "blaming the developer",
      "following dirty data",
      "reading tea leaves in the AST",
      "trusting but verifying",
      "writing the CVE in my head",
    ],
    deliverable: "code-review-report",
  },
  osint: {
    id: "osint",
    label: "OSINT Investigation",
    short: "int",
    agent: "osint",
    glyph: "⌬",
    accent: "secondary",
    tagline: "Find what's already public — sources, confidence, provenance",
    placeholders: {
      normal: [
        "Profile acme-corp.com leadership",
        "Find exposed credentials tied to this org",
        "Correlate these 3 personas across platforms",
      ],
      shell: ["whois example.com", "amass enum -d example.com", "theHarvester -d example.com -b all"],
    },
    thinking: [
      "pivoting on a breadcrumb",
      "asking the Wayback Machine",
      "fingerprinting the fingerprint",
      "connecting invisible dots",
      "following the money trail",
    ],
    deliverable: "intel-brief",
  },
  hacking: {
    id: "hacking",
    label: "Hacking (raw)",
    short: "h4x",
    agent: "hacking",
    glyph: "⚑",
    accent: "warning",
    tagline: "Just hack — no ceremony, no report, full speed",
    placeholders: {
      normal: [
        "10.10.11.42 — root it",
        "http://chal.ctf:1337 — flag is in /flag",
        "reverse this binary, get the flag",
        "dumped this hash, crack it",
      ],
      shell: ["nmap -sCV -T4 10.10.11.42", "gdb -q ./bin", "hashcat -m 1000 hash.txt rockyou.txt"],
    },
    thinking: [
      "knocking on /bin/sh",
      "gifting a shell",
      "asking root for a selfie",
      "reusing someone else's ROP chain",
      "touching grass (digitally)",
    ],
    deliverable: "shell",
  },
}

export namespace Kind {
  export const ALL: readonly KindPack[] = Object.values(PACKS)

  export function byId(id: string | undefined | null): KindPack | undefined {
    if (!id) return undefined
    if (!(id in PACKS)) return undefined
    return PACKS[id as KindId]
  }

  export function byAgent(agentName: string | undefined | null): KindPack | undefined {
    if (!agentName) return undefined
    return ALL.find((pack) => pack.agent === agentName)
  }

  export function resolve(
    agentName: string | undefined | null,
    fallback: KindId = "security",
  ): KindPack {
    return byAgent(agentName) ?? PACKS[fallback]
  }

  export const DEFAULT: KindId = "security"
}
