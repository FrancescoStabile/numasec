#!/usr/bin/env bun

import { Script } from "@numasec/script"
import { $ } from "bun"

const version = Script.version.replace(/^v/, "")
const tag = `v${version}`
const output = [`version=${version}`]

if (!Script.preview) {
  const sha = process.env.GITHUB_SHA ?? (await $`git rev-parse HEAD`.text()).trim()
  const file = `${process.cwd()}/UPCOMING_CHANGELOG.md`
  await $`bun script/changelog.ts --to ${sha}`.cwd(process.cwd()).nothrow()
  const body = await Bun.file(file)
    .text()
    .catch(() => "No notable changes")
  const dir = process.env.RUNNER_TEMP ?? "/tmp"
  const notesFile = `${dir}/numasec-release-notes.txt`
  await Bun.write(notesFile, body)
  await $`gh release create ${tag} -d --title ${tag} --notes-file ${notesFile}`.nothrow()
  const release = await $`gh release view ${tag} --json tagName,databaseId`.json()
  output.push(`release=${release.databaseId}`)
  output.push(`tag=${release.tagName}`)
} else if (Script.channel === "beta") {
  await $`gh release create ${tag} -d --title ${tag} --repo ${process.env.GH_REPO}`.nothrow()
  const release = await $`gh release view ${tag} --json tagName,databaseId --repo ${process.env.GH_REPO}`.json()
  output.push(`release=${release.databaseId}`)
  output.push(`tag=${release.tagName}`)
}

output.push(`repo=${process.env.GH_REPO}`)

if (process.env.GITHUB_OUTPUT) {
  await Bun.write(process.env.GITHUB_OUTPUT, output.join("\n"))
}

process.exit(0)
