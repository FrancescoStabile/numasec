---
name: forensics-kit
description: Digital forensics and incident response toolbox. Load when the operator asks about a pcap, a binary, a memory dump, a suspicious file, malware triage, IOC hunting, or post-incident analysis. Covers network (tshark), binaries (radare2, strings, binwalk, file, exiftool), memory (volatility), and pattern matching (YARA). All commands assume the artifact is local and disposable; never analyze in-place on a production system.
---

# Forensics & IR kit

**Rule of engagement.** Forensics work runs on **copies**. Never analyze a live victim system in place — `cp`/`dd` to a workspace, hash the original, and work on the copy. Every finding must reference the SHA256 of the artifact so chain-of-custody survives.

**Output contract.** Each IOC, carved artifact, or suspicious observation is a candidate observation (severity `medium`+ for IOCs, confidence `high` for exact matches, `medium` for heuristic hits).

## When to load

| Situation | Why |
|---|---|
| Operator drops a `.pcap`, `.pcapng`, `.bin`, `.dmp`, `.elf`, `.exe` | You need these tools |
| Post-compromise triage of a Linux/Windows host image | Memory + binaries |
| Suspicious file discovered by a scanner | strings / binwalk / file first |
| IOC hunt across a dataset | YARA rules |

## Toolbox

### 1. `file` + `exiftool` + `strings` — first-3-minutes triage

Before anything heavier, always identify the artifact and skim it.

```bash
file suspicious.bin
exiftool suspicious.bin
strings -n 8 suspicious.bin | head -200
strings -eL -n 8 suspicious.bin | head -100   # UTF-16LE (Windows PE)
```

**Interpretation.** `file` gives format/arch. `exiftool` surfaces author/tool metadata. `strings` reveals hard-coded URLs, C2 hostnames, file paths, error messages, library imports.

### 2. `binwalk` — Carve embedded content

```bash
binwalk -B firmware.bin          # signature scan
binwalk -e firmware.bin          # extract what it recognizes
binwalk -E firmware.bin          # entropy (encryption/compression indicator)
```

**Severity hints.** Firmware that carves cleanly to a shell script + a busybox → `high` if it contains credentials. Very-high uniform entropy → encrypted blob; flag and move on.

### 3. `tshark` — Packet capture analysis

```bash
# 1-line summary of protocols
tshark -r capture.pcapng -q -z io,phs

# HTTP requests
tshark -r capture.pcapng -Y http.request -T fields -e ip.dst -e http.host -e http.request.uri | sort -u

# DNS queries
tshark -r capture.pcapng -Y dns -T fields -e dns.qry.name | sort -u | head -50

# Suspicious destinations (non-RFC1918)
tshark -r capture.pcapng -T fields -e ip.dst | sort -u | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'

# TLS SNI (see what hosts are being contacted even under HTTPS)
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name | sort -u

# Extract objects (HTTP, SMB)
mkdir -p /tmp/tshark-export
tshark -r capture.pcapng --export-objects http,/tmp/tshark-export
```

**Interpretation.** Unknown SNI + sustained beacon interval ≈ C2 candidate. Non-RFC1918 destinations in an internal capture → exfiltration candidate.

### 4. `volatility` (Volatility 3) — Memory forensics

```bash
# Identify the profile implicitly (Volatility 3 auto-detects)
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.cmdline
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.malfind       # heuristics for injected code
vol -f memory.dmp windows.dlllist --pid <PID>
vol -f memory.dmp windows.hashdump      # SAM hashes

# Linux equivalents
vol -f memory.dmp linux.pslist
vol -f memory.dmp linux.bash            # recovered shell history
```

**Severity hints.** `malfind` hit with RWX region and MZ header → `high`, confidence `medium`. `hashdump` success → `critical` (credential exposure).

### 5. `radare2` — Binary RE

```bash
r2 -A suspicious.elf
# Inside r2:
#   afl       list functions
#   s main; pdf    disassemble main
#   iz        print strings
#   ii        imports
#   aaaa      deeper analysis
```

For one-liners:

```bash
rabin2 -z suspicious.elf        # strings in data sections
rabin2 -I suspicious.elf        # binary info
rabin2 -i suspicious.elf        # imports
```

### 6. YARA — Signature-based hunting

```bash
# Install: apt install yara
# Quick hunt using an existing ruleset
yara -r /opt/rules/index.yar suspicious.bin

# Directory scan
yara -r /opt/rules/index.yar /mnt/image/

# Author a rule from observed strings
cat > /tmp/demo.yar <<'EOF'
rule demo_c2 {
    meta:
        author = "numasec"
        description = "heuristic: hard-coded C2 host"
    strings:
        $s1 = "evil-c2.example.com"
        $s2 = { 4D 5A }   // MZ header
    condition:
        $s1 and $s2
}
EOF
yara /tmp/demo.yar suspicious.bin
```

**Good rulesets to start from (no key required):**
- YARA Rules project: https://github.com/Yara-Rules/rules
- Neo23x0 Signature-Base: https://github.com/Neo23x0/signature-base

### 7. Hashing + Chain-of-custody hygiene

```bash
sha256sum artifact.bin > artifact.bin.sha256
# Every observation references $(cut -d' ' -f1 artifact.bin.sha256)
```

Also keep a copy of `ls -la artifact.bin` and `stat artifact.bin` so mtime/ctime are recorded.

## Standard triage opening

For an unknown artifact:

1. `sha256sum` + `file` + `exiftool` + `strings | head`.
2. If it's a binary: `binwalk -E` (entropy) → `binwalk -e` if entropy is moderate → `radare2 -A` if interesting.
3. If it's a pcap: `tshark -z io,phs` → HTTP/DNS dumps → SNI → export objects.
4. If it's a memory image: `vol windows.info` → `pslist` → `netscan` → `malfind` → `hashdump`.
5. Run YARA with a generic ruleset.
6. Summarize IOCs (hosts, hashes, paths, mutexes, registry keys) into observations.
7. Cross-reference IOCs against `cve` tool (T10) and any open-source threat intel the operator has.

## What this skill does NOT do

- No live acquisition. Operator pre-acquires memory/disk.
- No cloud forensics (AWS CloudTrail parsing, GCP audit logs). Those need a dedicated skill pack.
- No automated malware detonation / sandboxing. Use Cuckoo/CAPE externally if needed.

## Escalation

After triage:

- If a binary has exploitable defects → hand off to the `hacking` agent via `task` tool.
- If an IR finding needs remediation code changes → hand off to the `appsec` agent.
- If the pcap shows sustained C2 → open a parallel threat-intel subtask (`security` agent).
