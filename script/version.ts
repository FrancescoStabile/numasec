#!/usr/bin/env bun

import path from "path"

const root = path.resolve(import.meta.dir, "..")
const pkg = await Bun.file(path.join(root, "packages/numasec/package.json")).json()
const requested = process.env.NUMASEC_VERSION || process.env.GITHUB_REF_NAME || pkg.version
const version = requested.replace(/^v/, "")
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error(`invalid release version: ${requested}`)
}
const tag = `v${version}`
const repo = process.env.GH_REPO ?? "FrancescoStabile/numasec"
const output = [`version=${version}`, `tag=${tag}`, `repo=${repo}`]

if (process.env.GITHUB_OUTPUT) {
  await Bun.write(process.env.GITHUB_OUTPUT, `${output.join("\n")}\n`)
}

process.exit(0)
