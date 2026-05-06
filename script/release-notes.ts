#!/usr/bin/env bun

import path from "path"
import { parseArgs } from "util"

const root = path.resolve(import.meta.dir, "..")

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    version: { type: "string", short: "v" },
    output: { type: "string", short: "o" },
    print: { type: "boolean", default: false },
  },
})

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function extractChangelogSection(changelog: string, version: string) {
  const escaped = escapeRegExp(version.replace(/^v/, ""))
  const header = new RegExp(`^##\\s+\\[?v?${escaped}\\]?(?:\\s|$)`, "im")
  const match = header.exec(changelog)
  if (!match) return undefined

  const start = match.index + match[0].length
  const rest = changelog.slice(start)
  const next = /^##\s+/im.exec(rest)
  return rest.slice(0, next ? next.index : undefined).trim()
}

const version = (values.version ?? process.env.NUMASEC_VERSION ?? process.env.GITHUB_REF_NAME ?? "").replace(/^v/, "")
if (!version) {
  throw new Error("release notes require --version, NUMASEC_VERSION, or GITHUB_REF_NAME")
}

const changelogPath = path.join(root, "CHANGELOG.md")
const changelog = await Bun.file(changelogPath).text()
const section = extractChangelogSection(changelog, version)

if (!section) {
  throw new Error(`CHANGELOG.md is missing a release section for ${version}`)
}

const body = `# numasec v${version}\n\n${section}\n`

if (values.output) {
  await Bun.write(path.resolve(values.output), body)
}

if (values.print || !values.output) {
  process.stdout.write(body)
}
