import type { MiddlewareHandler } from "hono"
import type { UpgradeWebSocket } from "hono/ws"
import { Instance } from "@/project/instance"
import { InstanceBootstrap } from "@/project/bootstrap"
import { Session } from "@/session"
import { SessionID } from "@/session/schema"
import { AppRuntime } from "@/effect/app-runtime"
import { AppFileSystem } from "@numasec/shared/filesystem"

function getSessionID(url: URL) {
  if (url.pathname === "/session/status") return null

  const id = url.pathname.match(/^\/session\/([^/]+)(?:\/|$)/)?.[1]
  if (!id) return null

  return SessionID.make(id)
}

export function WorkspaceRouterMiddleware(upgrade: UpgradeWebSocket): MiddlewareHandler {
  return async (c, next) => {
    const raw = c.req.query("directory") || c.req.header("x-numasec-directory") || process.cwd()
    const directory = AppFileSystem.resolve(
      (() => {
        try {
          return decodeURIComponent(raw)
        } catch {
          return raw
        }
      })(),
    )

    return Instance.provide({
      directory,
      init: () => AppRuntime.runPromise(InstanceBootstrap),
      async fn() {
        return next()
      },
    })
  }
}
