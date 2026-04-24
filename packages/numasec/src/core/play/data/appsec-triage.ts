import type { Play } from "../play"

const play: Play = {
  id: "appsec-triage",
  name: "Application Security Triage",
  description:
    "Triage a repository with deterministic repo-marker detection, lightweight grep checks for common vulnerability patterns, and WSTG input-validation mapping.",
  args: [
    { name: "path", required: true, type: "string", description: "local repository path to triage" },
  ],
  steps: [
    {
      kind: "tool",
      label: "Detect Node markers",
      tool: "glob",
      args: { pattern: "package.json", path: "{{path}}" },
    },
    {
      kind: "tool",
      label: "Detect Python markers",
      tool: "glob",
      args: { pattern: "{pyproject.toml,requirements.txt}", path: "{{path}}" },
    },
    {
      kind: "tool",
      label: "Detect Go markers",
      tool: "glob",
      args: { pattern: "go.mod", path: "{{path}}" },
    },
    {
      kind: "tool",
      label: "Detect Rust markers",
      tool: "glob",
      args: { pattern: "Cargo.toml", path: "{{path}}" },
    },
    {
      kind: "tool",
      label: "Detect JVM markers",
      tool: "glob",
      args: { pattern: "{pom.xml,build.gradle}", path: "{{path}}" },
    },
    {
      kind: "tool",
      label: "Detect PHP markers",
      tool: "glob",
      args: { pattern: "composer.json", path: "{{path}}" },
    },
    {
      kind: "tool",
      label: "Find hard-coded secrets",
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern:
          "(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,}|api[_-]?key\\s*[:=]\\s*[\\\"'][^\\\"']{16,}|password\\s*[:=]\\s*[\\\"'][^\\\"']{4,})",
      },
    },
    {
      kind: "tool",
      label: "Find dynamic code execution patterns",
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern: "\\beval\\s*\\(|\\bexec\\s*\\(|Function\\s*\\(|new Function\\(",
      },
    },
    {
      kind: "tool",
      label: "Find unsafe deserialization patterns",
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern: "pickle\\.loads|yaml\\.load\\b|ObjectInputStream|Marshal\\.load|unserialize\\(",
      },
    },
    {
      kind: "tool",
      label: "Find SQL string concatenation patterns",
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern:
          "(SELECT|INSERT|UPDATE|DELETE)\\s+[^;]*['\\\"]\\s*\\+|query\\([^)]*\\$\\{|execute\\([^)]*%s",
      },
    },
    {
      kind: "tool",
      label: "Map to WSTG input validation",
      tool: "methodology",
      args: { framework: "wstg", phase: "WSTG-INPV" },
    },
  ],
}

export default play
