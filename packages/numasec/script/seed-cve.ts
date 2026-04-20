#!/usr/bin/env bun
/**
 * Seeds assets/cve/index.json.gz with a handful of well-known, high-impact
 * CVEs so the `cve` tool works on a fresh checkout before the first run of
 * the cve-refresh workflow.
 *
 * Run from repo root: `bun run packages/numasec/script/seed-cve.ts`
 */

import { gzipSync } from "node:zlib"
import path from "node:path"
import { fileURLToPath } from "node:url"
import fs from "node:fs"

type Severity = "low" | "medium" | "high" | "critical"

type Entry = {
  id: string
  severity: Severity
  cvss: number
  summary: string
  cpe: string[]
  published: string
}

const SUMMARY_MAX = 280

function trim(summary: string): string {
  return summary.length <= SUMMARY_MAX ? summary : summary.slice(0, SUMMARY_MAX - 1).trimEnd() + "…"
}

const SEED: Entry[] = [
  {
    id: "CVE-2021-44228",
    severity: "critical",
    cvss: 10.0,
    summary: trim(
      "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding 2.12.2, 2.12.3, 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers (Log4Shell).",
    ),
    cpe: ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
    published: "2021-12-10T00:00:00Z",
  },
  {
    id: "CVE-2014-0160",
    severity: "high",
    cvss: 7.5,
    summary: trim(
      "The TLS/DTLS heartbeat extension in OpenSSL 1.0.1 before 1.0.1g does not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory (Heartbleed).",
    ),
    cpe: ["cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*"],
    published: "2014-04-07T00:00:00Z",
  },
  {
    id: "CVE-2014-6271",
    severity: "critical",
    cvss: 9.8,
    summary: trim(
      "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via crafted environment (Shellshock).",
    ),
    cpe: ["cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*"],
    published: "2014-09-24T00:00:00Z",
  },
  {
    id: "CVE-2017-5638",
    severity: "critical",
    cvss: 10.0,
    summary: trim(
      "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 mishandles file upload, allowing remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header (Equifax breach).",
    ),
    cpe: ["cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*"],
    published: "2017-03-10T00:00:00Z",
  },
  {
    id: "CVE-2022-0847",
    severity: "high",
    cvss: 7.8,
    summary: trim(
      "A flaw in the way the Linux kernel's copy_page_to_iter_pipe and push_pipe functions initialized pipe_buffer flags allowed a local unprivileged user to overwrite data in arbitrary read-only files, enabling privilege escalation (Dirty Pipe).",
    ),
    cpe: ["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"],
    published: "2022-03-07T00:00:00Z",
  },
  {
    id: "CVE-2019-0708",
    severity: "critical",
    cvss: 9.8,
    summary: trim(
      "A remote code execution vulnerability exists in Remote Desktop Services (formerly Terminal Services) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests (BlueKeep).",
    ),
    cpe: ["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
    published: "2019-05-14T00:00:00Z",
  },
  {
    id: "CVE-2020-1472",
    severity: "critical",
    cvss: 10.0,
    summary: trim(
      "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller using the Netlogon Remote Protocol (MS-NRPC), allowing complete domain takeover (Zerologon).",
    ),
    cpe: ["cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*"],
    published: "2020-08-17T00:00:00Z",
  },
  {
    id: "CVE-2022-22965",
    severity: "critical",
    cvss: 9.8,
    summary: trim(
      "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding. The exploit requires the application to run on Tomcat as a WAR deployment and uses specially crafted parameters (Spring4Shell).",
    ),
    cpe: ["cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*"],
    published: "2022-04-01T00:00:00Z",
  },
  {
    id: "CVE-2023-23397",
    severity: "critical",
    cvss: 9.8,
    summary: trim(
      "Microsoft Outlook Elevation of Privilege vulnerability: a crafted calendar appointment with a UNC path in PidLidReminderFileParameter causes Outlook to connect to an attacker-controlled SMB server and leak the Net-NTLMv2 hash without user interaction.",
    ),
    cpe: ["cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*"],
    published: "2023-03-14T00:00:00Z",
  },
  {
    id: "CVE-2024-3094",
    severity: "critical",
    cvss: 10.0,
    summary: trim(
      "Malicious code was discovered in the upstream tarballs of xz-utils 5.6.0 and 5.6.1, including liblzma. Through a series of obfuscations the build process extracts a prebuilt object that modifies functions used by OpenSSH's sshd, enabling backdoor authentication bypass.",
    ),
    cpe: ["cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"],
    published: "2024-03-29T00:00:00Z",
  },
]

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(__dirname, "../../..")
const out = path.join(root, "assets/cve/index.json.gz")

fs.mkdirSync(path.dirname(out), { recursive: true })
const raw = Buffer.from(JSON.stringify(SEED))
const gz = gzipSync(raw, { level: 9 })
fs.writeFileSync(out, gz)

console.log(`wrote ${out}`)
console.log(`entries: ${SEED.length}`)
console.log(`raw:     ${raw.byteLength} bytes`)
console.log(`gzipped: ${gz.byteLength} bytes`)
