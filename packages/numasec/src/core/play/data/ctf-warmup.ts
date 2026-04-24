import type { Play } from "../play"

const play: Play = {
  id: "ctf-warmup",
  name: "CTF Warm-Up",
  description:
    "Warm up on a local challenge artifact with primary forensics-kit triage, optional local metadata/string enrichment, and MITRE artifact context.",
  args: [
    { name: "target", required: true, type: "string", description: "local path to the challenge artifact" },
  ],
  steps: [
    {
      kind: "skill",
      label: "Primary artifact triage with forensics-kit",
      skill: "forensics-kit",
      brief:
        "triage the local challenge artifact at {{target}}; run file, strings (min-len 8), and exiftool where useful; use binwalk/xxd only if the artifact looks binary; summarize type, metadata, interesting strings, entropy clues, and likely next moves",
    },
    {
      kind: "tool",
      label: "Local file and strings enrichment",
      tool: "bash",
      args: {
        command:
          "file {{target}} 2>/dev/null; echo ---; strings -n 8 {{target}} 2>/dev/null | head -n 80",
      },
      requires: [
        { kind: "binary", id: "file", label: "file binary", missingAs: "optional" },
        { kind: "binary", id: "strings", label: "strings binary", missingAs: "optional" },
      ],
    },
    {
      kind: "tool",
      label: "Exif metadata enrichment",
      tool: "bash",
      args: { command: "exiftool {{target}} 2>/dev/null" },
      requires: [{ kind: "binary", id: "exiftool", label: "exiftool binary", missingAs: "optional" }],
    },
    {
      kind: "tool",
      label: "Map to MITRE artifact context",
      tool: "methodology",
      args: { framework: "mitre", query: "{{target}}" },
    },
  ],
}

export default play
