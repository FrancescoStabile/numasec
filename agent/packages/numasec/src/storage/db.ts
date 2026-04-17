import { type SQLiteBunDatabase } from "drizzle-orm/bun-sqlite"
import { migrate } from "drizzle-orm/bun-sqlite/migrator"
import { type SQLiteTransaction } from "drizzle-orm/sqlite-core"
export * from "drizzle-orm"
import { Context } from "../util/context"
import { lazy } from "../util/lazy"
import { Global } from "../global"
import { Log } from "../util/log"
import { NamedError } from "@numasec/util/error"
import z from "zod"
import path from "path"
import { readFileSync, readdirSync, existsSync } from "fs"
import { chmodSync } from "fs"
import { Installation } from "../installation"
import { Flag } from "../flag/flag"
import { iife } from "@/util/iife"
import { init } from "#db"

declare const NUMASEC_MIGRATIONS: { sql: string; timestamp: number; name: string }[] | undefined

export const NotFoundError = NamedError.create(
  "NotFoundError",
  z.object({
    message: z.string(),
  }),
)

const log = Log.create({ service: "db" })

export namespace Database {
  export function getChannelPath() {
    const channel = Installation.CHANNEL
    if (["latest", "beta", "local"].includes(channel) || Flag.NUMASEC_DISABLE_CHANNEL_DB)
      return path.join(Global.Path.data, "numasec.db")
    const safe = channel.replace(/[^a-zA-Z0-9._-]/g, "-")
    return path.join(Global.Path.data, `numasec-${safe}.db`)
  }

  export const Path = iife(() => {
    if (Flag.NUMASEC_DB) {
      if (Flag.NUMASEC_DB === ":memory:" || path.isAbsolute(Flag.NUMASEC_DB)) return Flag.NUMASEC_DB
      return path.join(Global.Path.data, Flag.NUMASEC_DB)
    }
    return getChannelPath()
  })

  export type Transaction = SQLiteTransaction<"sync", void>

  type Client = ReturnType<typeof init>

  type Journal = { sql: string; timestamp: number; name: string }[]
  const core = ["project", "session", "message", "part"] as const

  function time(tag: string) {
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(tag)
    if (!match) return 0
    return Date.UTC(
      Number(match[1]),
      Number(match[2]) - 1,
      Number(match[3]),
      Number(match[4]),
      Number(match[5]),
      Number(match[6]),
    )
  }

  function migrations(dir: string): Journal {
    const dirs = readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)

    const sql = dirs
      .map((name) => {
        const file = path.join(dir, name, "migration.sql")
        if (!existsSync(file)) return
        return {
          sql: readFileSync(file, "utf-8"),
          timestamp: time(name),
          name,
        }
      })
      .filter(Boolean) as Journal

    return sql.sort((a, b) => a.timestamp - b.timestamp)
  }

  function tables(db: Client) {
    return db.$client.query("select name from sqlite_master where type='table'").all() as { name: string }[]
  }

  export function assertSkip(db: Client, entries: Journal) {
    const names = new Set(tables(db).map((row) => row.name))
    const missing = core.filter((name) => !names.has(name))
    if (missing.length > 0) {
      throw new Error(
        `NUMASEC_SKIP_MIGRATIONS requires an existing database schema; missing tables: ${missing.join(", ")}`,
      )
    }
    if (!names.has("__drizzle_migrations")) {
      throw new Error("NUMASEC_SKIP_MIGRATIONS requires an existing drizzle migration journal")
    }
    const row = db.$client.query("select count(*) as count from __drizzle_migrations").get() as { count: number } | null
    const count = Number(row?.count ?? 0)
    if (count < entries.length) {
      throw new Error(
        `NUMASEC_SKIP_MIGRATIONS requires a fully migrated database; applied ${count} of ${entries.length} migrations`,
      )
    }
  }

  function harden(path: string, mode: number) {
    if (process.platform === "win32") return
    if (!existsSync(path)) return
    chmodSync(path, mode)
  }

  function hardenDatabaseArtifacts(path: string) {
    harden(path, 0o600)
    harden(`${path}-wal`, 0o600)
    harden(`${path}-shm`, 0o600)
  }

  export const Client = lazy(() => {
    log.info("opening database", { path: Path })

    const db = init(Path)
    hardenDatabaseArtifacts(Path)

    db.run("PRAGMA journal_mode = WAL")
    db.run("PRAGMA synchronous = NORMAL")
    db.run("PRAGMA busy_timeout = 5000")
    db.run("PRAGMA cache_size = -64000")
    db.run("PRAGMA foreign_keys = ON")
    db.run("PRAGMA wal_checkpoint(PASSIVE)")

    // Apply schema migrations
    const entries =
      typeof NUMASEC_MIGRATIONS !== "undefined"
        ? NUMASEC_MIGRATIONS
        : migrations(path.join(import.meta.dirname, "../../migration"))
    if (entries.length > 0) {
      log.info("applying migrations", {
        count: entries.length,
        mode: typeof NUMASEC_MIGRATIONS !== "undefined" ? "bundled" : "dev",
      })
      if (Flag.NUMASEC_SKIP_MIGRATIONS) {
        assertSkip(db, entries)
        log.warn("skipping migrations on an already-migrated database", {
          count: entries.length,
          path: Path,
        })
      }
      if (!Flag.NUMASEC_SKIP_MIGRATIONS) {
        migrate(db, entries)
      }
    }

    hardenDatabaseArtifacts(Path)

    return db
  })

  export function close() {
    Client().$client.close()
    Client.reset()
  }

  export type TxOrDb = Transaction | Client

  const ctx = Context.create<{
    tx: TxOrDb
    effects: (() => void | Promise<void>)[]
  }>("database")

  export function use<T>(callback: (trx: TxOrDb) => T): T {
    try {
      return callback(ctx.use().tx)
    } catch (err) {
      if (err instanceof Context.NotFound) {
        const effects: (() => void | Promise<void>)[] = []
        const result = ctx.provide({ effects, tx: Client() }, () => callback(Client()))
        for (const effect of effects) effect()
        return result
      }
      throw err
    }
  }

  export function effect(fn: () => any | Promise<any>) {
    try {
      ctx.use().effects.push(fn)
    } catch {
      fn()
    }
  }

  type NotPromise<T> = T extends Promise<any> ? never : T

  export function transaction<T>(
    callback: (tx: TxOrDb) => NotPromise<T>,
    options?: {
      behavior?: "deferred" | "immediate" | "exclusive"
    },
  ): NotPromise<T> {
    try {
      return callback(ctx.use().tx)
    } catch (err) {
      if (err instanceof Context.NotFound) {
        const effects: (() => void | Promise<void>)[] = []
        const result = Client().transaction(
          (tx: TxOrDb) => {
            return ctx.provide({ tx, effects }, () => callback(tx))
          },
          { behavior: options?.behavior },
        )
        for (const effect of effects) effect()
        return result as NotPromise<T>
      }
      throw err
    }
  }
}
