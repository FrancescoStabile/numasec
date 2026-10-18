import { listen } from "../../src/util/rpc"

// Mirrors src/cli/cmd/tui/worker.ts: the worker hits a top-level await before
// it installs its RPC listener. Messages that arrive during that window are
// dropped by the runtime unless the client waits for the ready handshake.
await Bun.sleep(150)

listen({
  echo: (input: string) => `echo:${input}`,
})
