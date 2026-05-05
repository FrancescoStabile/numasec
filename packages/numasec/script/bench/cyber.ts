import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { parseArgs, passesScenario, scenarioFailures, scenariosFor, type BenchResult, type Scenario } from "./cyber-lib"

function pkgRoot() {
  return join(import.meta.dir, "..", "..")
}

function resultFiles() {
  const root = pkgRoot()
  return new Set(
    readdirSync(root)
      .filter((name) => /^bench-results-\d+\.json$/.test(name))
      .map((name) => join(root, name)),
  )
}

function latestNewResult(before: Set<string>) {
  const root = pkgRoot()
  const files = readdirSync(root)
    .filter((name) => /^bench-results-\d+\.json$/.test(name))
    .map((name) => join(root, name))
    .filter((file) => !before.has(file))
    .sort()
  if (files.length === 0) throw new Error("benchmark run did not produce a result file")
  const file = files[files.length - 1]
  if (!existsSync(file)) throw new Error(`missing benchmark result file: ${file}`)
  return {
    file,
    result: JSON.parse(readFileSync(file, "utf8")) as BenchResult,
  }
}

async function runScenario(scenario: Scenario) {
  const before = resultFiles()
  const proc = Bun.spawn(["bun", "run", "script/bench/run.ts", "--scenario", scenario], {
    cwd: pkgRoot(),
    stdout: "inherit",
    stderr: "inherit",
  })
  const exitCode = await proc.exited
  if (exitCode !== 0) {
    throw new Error(`scenario ${scenario} failed with exit code ${exitCode}`)
  }
  return latestNewResult(before)
}

function printSummary(results: Array<{ file: string; result: BenchResult }>) {
  console.log("")
  console.log("Cyber benchmark summary")
  for (const item of results) {
    const gate = passesScenario(item.result) ? "PASS" : "FAIL"
    const detail = scenarioFailures(item.result)
    console.log(
      `- ${item.result.scenario}: ${gate} (${item.result.result.score}/${item.result.result.max})${detail.length ? ` · ${detail.join(",")}` : ""} · ${item.file.split("/").slice(-1)[0]}`,
    )
  }
}

async function main() {
  const { domain } = parseArgs(process.argv.slice(2))
  const scenarios = scenariosFor(domain)
  const results: Array<{ file: string; result: BenchResult }> = []

  for (const scenario of scenarios) {
    console.log(`[bench:cyber] running ${scenario}`)
    results.push(await runScenario(scenario))
  }

  printSummary(results)

  const failed = results.filter((item) => !passesScenario(item.result))
  if (failed.length > 0) {
    console.error(
      `[bench:cyber] release gate failed for ${failed.map((item) => item.result.scenario).join(", ")}`,
    )
    process.exit(1)
  }

  console.log(`[bench:cyber] release gate passed for domain=${domain}`)
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
