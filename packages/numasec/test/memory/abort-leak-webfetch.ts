import { abortAfterAny } from "../../src/util/abort"

const MB = 1024 * 1024
const ITERATIONS = 50

const heap = () => {
  Bun.gc(true)
  return process.memoryUsage().heapUsed / MB
}

const url = "data:text/plain,hello%20from%20local"

async function run() {
  const { signal, clearTimeout } = abortAfterAny(30000, new AbortController().signal)
  try {
    const response = await fetch(url, { signal })
    await response.text()
  } finally {
    clearTimeout()
  }
}

try {
  await run()
  Bun.sleepSync(100)
  const baseline = heap()

  for (let i = 0; i < ITERATIONS; i++) {
    await run()
  }

  Bun.sleepSync(100)
  const after = heap()
  process.stdout.write(JSON.stringify({ baseline, after, growth: after - baseline }))
} finally {
  process.exit(0)
}
