import type { Play } from "../play"

const play: Play = {
  id: "ctf-warmup",
  name: "CTF Warm-Up",
  description:
    "Warm-up on a CTF challenge file or URL: file/strings/exiftool via forensics-kit skill, identify category, suggest starting moves.",
  args: [
    { name: "target", required: true, type: "string", description: "path to challenge artifact or URL" },
  ],
  steps: [
    {
      skill: "forensics-kit",
      brief:
        "run file, strings (min-len 8), and exiftool on {{target}}; also run binwalk/xxd if it looks binary; summarize magic bytes, entropy, embedded files",
    },
    {
      tool: "bash",
      args: {
        command:
          "{ file {{target}} 2>/dev/null; echo ---; strings -n 8 {{target}} 2>/dev/null | head -n 80; echo ---; command -v exiftool >/dev/null && exiftool {{target}} 2>/dev/null; } || true",
        description: "quick triage fallback if forensics-kit skill is unavailable",
      },
    },
    {
      tool: "methodology",
      args: { framework: "mitre", query: "{{target}}" },
    },
  ],
}

export default play
