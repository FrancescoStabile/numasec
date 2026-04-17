import { $ } from "bun"
import { beforeEach, afterEach, describe, expect, test } from "bun:test"
import { Database as Sqlite } from "bun:sqlite"
import { drizzle } from "drizzle-orm/bun-sqlite"
import { migrate } from "drizzle-orm/bun-sqlite/migrator"
import path from "path"
import fs from "fs/promises"
import { existsSync, readFileSync, readdirSync } from "fs"
import { Global } from "../../src/global"
import { Storage } from "../../src/storage/storage"
import { JsonMigration } from "../../src/storage/json-migration"
import { ProjectTable } from "../../src/project/project.sql"
import { SessionTable, MessageTable, PartTable } from "../../src/session/session.sql"

function journal() {
  const dir = path.join(import.meta.dirname, "../../migration")
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({
      sql: readFileSync(path.join(dir, entry.name, "migration.sql"), "utf-8"),
      timestamp: Number(entry.name.split("_")[0]),
      name: entry.name,
    }))
    .sort((a, b) => a.timestamp - b.timestamp)
}

function createDb() {
  const sqlite = new Sqlite(":memory:")
  migrate(drizzle({ client: sqlite }), journal())
  return sqlite
}

async function repo(dir: string) {
  await fs.mkdir(dir, { recursive: true })
  await Bun.write(path.join(dir, "README.md"), "fixture\n")
  await $`git init`.cwd(dir)
  await $`git config user.email fixture@example.com`.cwd(dir)
  await $`git config user.name fixture`.cwd(dir)
  await $`git add README.md`.cwd(dir)
  await $`git commit -m "init"`.cwd(dir)
  return await $`git rev-list --max-parents=0 --all`.cwd(dir).text().then((x) => x.trim())
}

describe("legacy storage bootstrap", () => {
  const data = Global.Path.data
  const storageDir = path.join(data, "storage")
  const legacyDir = path.join(data, "project")
  let sqlite: Sqlite

  beforeEach(async () => {
    sqlite = createDb()
    await fs.rm(storageDir, { recursive: true, force: true })
    await fs.rm(legacyDir, { recursive: true, force: true })
  })

  afterEach(async () => {
    sqlite.close()
    await fs.rm(storageDir, { recursive: true, force: true })
    await fs.rm(legacyDir, { recursive: true, force: true })
    await fs.rm(path.join(data, "worktree"), { recursive: true, force: true })
  })

  test("restructures legacy project storage before sqlite import", async () => {
    const worktree = path.join(data, "worktree")
    const projectID = await repo(worktree)
    const projectDir = path.join(legacyDir, "legacy")
    const sessionID = "ses_legacy"
    const messageID = "msg_legacy"
    const partID = "prt_legacy"

    await Bun.write(
      path.join(projectDir, "storage", "session", "info", `${sessionID}.json`),
      JSON.stringify({
        id: sessionID,
        slug: "legacy",
        directory: worktree,
        title: "Legacy Session",
        version: "1.0.0",
        time: { created: 1700000000000, updated: 1700000001000 },
      }),
    )
    await Bun.write(
      path.join(projectDir, "storage", "session", "message", sessionID, `${messageID}.json`),
      JSON.stringify({
        id: messageID,
        sessionID,
        role: "user",
        agent: "default",
        model: { providerID: "openai", modelID: "gpt-4.1" },
        path: { root: worktree },
        time: { created: 1700000000000, updated: 1700000001000 },
      }),
    )
    await Bun.write(
      path.join(projectDir, "storage", "session", "part", sessionID, messageID, `${partID}.json`),
      JSON.stringify({
        id: partID,
        messageID,
        sessionID,
        type: "text",
        text: "legacy",
      }),
    )

    await Storage.init()

    expect(existsSync(path.join(storageDir, "project", `${projectID}.json`))).toBe(true)
    expect(existsSync(path.join(storageDir, "session", projectID, `${sessionID}.json`))).toBe(true)
    expect(existsSync(path.join(storageDir, "message", sessionID, `${messageID}.json`))).toBe(true)
    expect(existsSync(path.join(storageDir, "part", messageID, `${partID}.json`))).toBe(true)
    expect(await Bun.file(path.join(storageDir, "migration")).text()).toBe("2")

    const stats = await JsonMigration.run(sqlite)
    expect(stats.projects).toBe(1)
    expect(stats.sessions).toBe(1)
    expect(stats.messages).toBe(1)
    expect(stats.parts).toBe(1)

    const db = drizzle({ client: sqlite })
    expect(db.select().from(ProjectTable).all()).toHaveLength(1)
    expect(db.select().from(SessionTable).all()).toHaveLength(1)
    expect(db.select().from(MessageTable).all()).toHaveLength(1)
    expect(db.select().from(PartTable).all()).toHaveLength(1)
  })

  test("does not advance the legacy migration marker on failure", async () => {
    await Bun.write(path.join(legacyDir, "broken", "storage", "session", "message", "ses_old", "msg_old.json"), "{ nope")

    await expect(Storage.init()).rejects.toThrow()
    expect(existsSync(path.join(storageDir, "migration"))).toBe(false)
  })
})
