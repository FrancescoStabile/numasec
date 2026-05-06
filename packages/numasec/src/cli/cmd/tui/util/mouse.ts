import os from "os"

export function shouldEnableMouseMovement(input?: {
  platform?: NodeJS.Platform
  release?: string
  env?: NodeJS.ProcessEnv
}) {
  const platform = input?.platform ?? process.platform
  const release = input?.release ?? os.release()
  const env = input?.env ?? process.env

  if (platform !== "linux") return true
  if (release.toLowerCase().includes("wsl")) return false
  if (env["WSL_DISTRO_NAME"]) return false
  return true
}
