import type { Play } from "../play"

const play: Play = {
  id: "appsec-triage",
  name: "Application Security Triage",
  description:
    "Triage a repository: detect language/framework, grep for common vuln patterns (hard-coded secrets, eval, deserialization, SQL concat), and suggest top-3 focus areas.",
  args: [
    { name: "path", required: true, type: "string", description: "local repository path to triage" },
  ],
  steps: [
    {
      tool: "bash",
      args: {
        command:
          "cd {{path}} && (test -f package.json && echo node || true; test -f pyproject.toml -o -f requirements.txt && echo python || true; test -f go.mod && echo go || true; test -f Cargo.toml && echo rust || true; test -f pom.xml -o -f build.gradle && echo jvm || true; test -f composer.json && echo php || true) | sort -u",
        description: "detect language/framework markers",
      },
    },
    {
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern: "(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,}|api[_-]?key\\s*[:=]\\s*[\"'][^\"']{16,}|password\\s*[:=]\\s*[\"'][^\"']{4,})",
        description: "hard-coded secrets",
      },
    },
    {
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern: "\\beval\\s*\\(|\\bexec\\s*\\(|Function\\s*\\(|new Function\\(",
        description: "dynamic code execution",
      },
    },
    {
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern: "pickle\\.loads|yaml\\.load\\b|ObjectInputStream|Marshal\\.load|unserialize\\(",
        description: "unsafe deserialization",
      },
    },
    {
      tool: "grep",
      args: {
        path: "{{path}}",
        pattern:
          "(SELECT|INSERT|UPDATE|DELETE)\\s+[^;]*['\"]\\s*\\+|query\\([^)]*\\$\\{|execute\\([^)]*%s",
        description: "SQL string concatenation",
      },
    },
    {
      tool: "methodology",
      args: { framework: "wstg", phase: "WSTG-INPV" },
    },
  ],
}

export default play
