import { describe, expect, test } from "bun:test"
import path from "path"
import { readFileSync, readdirSync, statSync } from "fs"
import { Database as Sqlite } from "bun:sqlite"
import { drizzle } from "drizzle-orm/bun-sqlite"
import { migrate } from "drizzle-orm/bun-sqlite/migrator"
import { Global } from "../../src/global"
import { Installation } from "../../src/installation"
import { Database } from "../../src/storage/db"

function entries() {
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

function seed(count = entries().length) {
  const sqlite = new Sqlite(":memory:")
  const db = drizzle({ client: sqlite })
  migrate(db, entries().slice(0, count))
  return db
}

describe("Database.Path", () => {
  test("returns database path for the current channel", () => {
    const expected = ["latest", "beta", "local"].includes(Installation.CHANNEL)
      ? path.join(Global.Path.data, "numasec.db")
      : path.join(Global.Path.data, `numasec-${Installation.CHANNEL.replace(/[^a-zA-Z0-9._-]/g, "-")}.db`)
    expect(Database.getChannelPath()).toBe(expected)
  })

  test("hardens data directory and database file permissions on unix", () => {
    Database.Client()

    if (process.platform === "win32") return

    const data = statSync(Global.Path.data)
    expect(data.mode & 0o777).toBe(0o700)

    if (Database.Path === ":memory:") return

    const db = statSync(Database.Path)
    expect(db.mode & 0o777).toBe(0o600)
  })

  test("rejects NUMASEC_SKIP_MIGRATIONS on a schema-less database", () => {
    const sqlite = new Sqlite(":memory:")
    const db = drizzle({ client: sqlite })

    expect(() => Database.assertSkip(db, entries())).toThrow("NUMASEC_SKIP_MIGRATIONS")

    sqlite.close()
  })

  test("rejects NUMASEC_SKIP_MIGRATIONS when migrations are missing", () => {
    const db = seed(1)

    expect(() => Database.assertSkip(db, entries())).toThrow("fully migrated")

    db.$client.close()
  })

  test("allows NUMASEC_SKIP_MIGRATIONS for a fully migrated database", () => {
    const db = seed()

    expect(() => Database.assertSkip(db, entries())).not.toThrow()

    db.$client.close()
  })
})
