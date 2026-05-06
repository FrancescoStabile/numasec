import { mkdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import type { BrokerDeps } from "./broker"
import type { KnowledgeResult } from "./types"

function cachePath(workspace: string, key: string) {
  return path.join(workspace, ".numasec", "knowledge-cache", `${key}.json`)
}

export function workspaceKnowledgeCache(workspace: string): Pick<BrokerDeps, "readCache" | "writeCache"> {
  return {
    readCache: async (key) => {
      try {
        const parsed = JSON.parse(await readFile(cachePath(workspace, key), "utf8")) as KnowledgeResult
        if (!parsed || !Array.isArray(parsed.cards)) return undefined
        return parsed
      } catch {
        return undefined
      }
    },
    writeCache: async (key, result) => {
      const file = cachePath(workspace, key)
      await mkdir(path.dirname(file), { recursive: true })
      await writeFile(file, JSON.stringify(result, null, 2))
    },
  }
}
