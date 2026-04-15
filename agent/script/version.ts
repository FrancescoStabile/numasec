#!/usr/bin/env bun

import { Script } from "@numasec/script"
import { $ } from "bun"

const output = [`version=${Script.version}`]
const repo = process.env.GH_REPO ?? "FrancescoStabile/numasec"
const tag = `v${Script.version}`

async function notes() {
  const tags = await $`git tag --list 'v*' --sort=-v:refname`
    .text()
    .then((x) =>
      x
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean),
    )
    .catch(() => [])
  const prev = tags.find((item) => item !== tag)
  if (!prev) return "Initial release"
  const log = await $`git log ${prev}..HEAD --format=%s -- packages/numasec packages/sdk packages/plugin packages/app sdks/vscode packages/extensions agent/github`
    .text()
    .then((x) =>
      x
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean)
        .filter((item) => !item.match(/^(ignore:|test:|chore:|ci:|release:)/i)),
    )
    .catch(() => [])
  if (log.length === 0) return `Changes since ${prev}\n\n- No notable changes`
  return [`Changes since ${prev}`, "", ...log.map((item) => `- ${item}`)].join("\n")
}

async function ensure(body: string) {
  const current = await $`gh release view ${tag} --json tagName,databaseId --repo ${repo}`
    .json()
    .catch(() => undefined)
  if (current) {
    return current as { tagName: string; databaseId: number }
  }

  const dir = process.env.RUNNER_TEMP ?? "/tmp"
  const notesFile = `${dir}/numasec-release-notes.txt`
  await Bun.write(notesFile, body)
  await $`gh release create ${tag} -d --title ${tag} --notes-file ${notesFile} --repo ${repo}`
  return (await $`gh release view ${tag} --json tagName,databaseId --repo ${repo}`.json()) as {
    tagName: string
    databaseId: number
  }
}

if (!Script.preview) {
  const release = await ensure(await notes())
  output.push(`release=${release.databaseId}`)
  output.push(`tag=${release.tagName}`)
} else if (Script.channel === "beta") {
  const release = await ensure("Beta preview release")
  output.push(`release=${release.databaseId}`)
  output.push(`tag=${release.tagName}`)
}

output.push(`repo=${repo}`)

if (process.env.GITHUB_OUTPUT) {
  await Bun.write(process.env.GITHUB_OUTPUT, output.join("\n"))
}

process.exit(0)
