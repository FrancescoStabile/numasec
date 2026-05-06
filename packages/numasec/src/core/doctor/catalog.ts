export type BinaryTier = "core" | "offensive"

export type BinarySpec = {
  name: string
  tier: BinaryTier
  note?: string
}

export type Requirement = {
  kind: "binary" | "runtime"
  id: string
  label: string
  required: boolean
}

export type CapabilitySpec = {
  id: string
  label: string
  requirements: Requirement[]
}

export const BINARIES: BinarySpec[] = [
  { name: "curl", tier: "core" },
  { name: "jq", tier: "core" },
  { name: "git", tier: "core" },
  { name: "rg", tier: "core" },
  { name: "nmap", tier: "offensive" },
  { name: "nuclei", tier: "offensive" },
  { name: "subfinder", tier: "offensive" },
  { name: "ffuf", tier: "offensive" },
  { name: "amass", tier: "offensive" },
  { name: "httpx", tier: "offensive" },
  { name: "gobuster", tier: "offensive" },
  { name: "sqlmap", tier: "offensive" },
  { name: "zap", tier: "offensive" },
  { name: "burpsuite", tier: "offensive" },
]

const browserRequired: Requirement = {
  kind: "runtime",
  id: "browser",
  label: "browser runtime",
  required: true,
}

const browserOptional: Requirement = {
  kind: "runtime",
  id: "browser",
  label: "browser runtime",
  required: false,
}

export const PLAY_CAPABILITIES: CapabilitySpec[] = [
  {
    id: "web-surface",
    label: "Web Surface Map",
    requirements: [browserOptional],
  },
  {
    id: "network-surface",
    label: "Network Surface Map",
    requirements: [],
  },
  {
    id: "appsec-triage",
    label: "Application Security Triage",
    requirements: [
      { kind: "binary", id: "git", label: "git", required: true },
      { kind: "binary", id: "rg", label: "rg", required: true },
    ],
  },
  {
    id: "appsec-web-triage",
    label: "AppSec Web Triage",
    requirements: [browserOptional],
  },
  {
    id: "osint-target",
    label: "Passive Target Profile",
    requirements: [
      { kind: "binary", id: "curl", label: "curl", required: true },
      { kind: "binary", id: "jq", label: "jq", required: true },
    ],
  },
  {
    id: "ctf-warmup",
    label: "CTF Warmup",
    requirements: [],
  },
]

export const VERTICAL_CAPABILITIES: CapabilitySpec[] = [
  {
    id: "repo-appsec",
    label: "Repository AppSec",
    requirements: [
      { kind: "binary", id: "git", label: "git", required: true },
      { kind: "binary", id: "rg", label: "rg", required: true },
    ],
  },
  {
    id: "browser-inspection",
    label: "Browser Inspection",
    requirements: [browserRequired],
  },
  {
    id: "active-web-testing",
    label: "Active Web Testing",
    requirements: [
      { kind: "binary", id: "nuclei", label: "nuclei", required: true },
      { kind: "binary", id: "ffuf", label: "ffuf", required: true },
      { kind: "binary", id: "sqlmap", label: "sqlmap", required: false },
      { kind: "binary", id: "gobuster", label: "gobuster", required: false },
      { kind: "binary", id: "httpx", label: "httpx", required: false },
    ],
  },
  {
    id: "network-recon",
    label: "Network Recon",
    requirements: [
      { kind: "binary", id: "nmap", label: "nmap", required: true },
      { kind: "binary", id: "subfinder", label: "subfinder", required: false },
      { kind: "binary", id: "amass", label: "amass", required: false },
    ],
  },
]
