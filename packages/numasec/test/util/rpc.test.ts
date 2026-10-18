import { afterEach, describe, expect, test } from "bun:test"
import { Rpc } from "../../src/util"
import { withTimeout } from "../../src/util/timeout"

type Echo = { echo: (input: string) => string }

describe("util.rpc", () => {
  let worker: Worker | undefined

  afterEach(() => {
    worker?.terminate()
    worker = undefined
  })

  test("a call made before the worker installs its listener is still answered", async () => {
    worker = new Worker(new URL("../fixture/rpc-slow-worker.ts", import.meta.url))
    const client = Rpc.client<Echo>(worker)

    // Sent while the worker is still inside its top-level await.
    const result = await withTimeout(client.call("echo", "early"), 3000)

    expect(result).toBe("echo:early")
  })

  test("ready resolves once the worker is listening, and calls keep working after it", async () => {
    worker = new Worker(new URL("../fixture/rpc-slow-worker.ts", import.meta.url))
    const client = Rpc.client<Echo>(worker)

    await withTimeout(client.ready, 3000)

    expect(await withTimeout(client.call("echo", "late"), 3000)).toBe("echo:late")
  })
})
