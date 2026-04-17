import { createEffect, createSignal, onCleanup, onMount, Show } from "solid-js"
import path from "path"
import os from "os"
import fs from "fs/promises"
import { useTheme } from "../context/theme"
import { InstallationVersion } from "@/installation/version"
import { BRAND } from "./glyph"

const FRAMES = 8
const FRAME_MS = 50
const HOLD_MS = 220
const FADE_MS = 80
const TOTAL_MS = FRAMES * FRAME_MS + HOLD_MS + FADE_MS

const NOISE_CHARS = "▓▒░█@#%&*=+-<>?/\\|^~"
const TARGET_LINES = [
  `${BRAND.wordmark} v${InstallationVersion}`,
  "operator-first · public brain · sacred scope",
]

function noiseLine(target: string, progress: number) {
  const reveal = Math.floor(target.length * progress)
  let out = ""
  for (let i = 0; i < target.length; i++) {
    const ch = target[i]
    if (ch === " " || i < reveal) out += ch
    else out += NOISE_CHARS[Math.floor(Math.random() * NOISE_CHARS.length)]
  }
  return out
}

function sentinelPath() {
  const base = process.env["XDG_CONFIG_HOME"] || path.join(os.homedir(), ".config")
  return path.join(base, "numasec", "boot-splash-seen")
}

async function shouldShow() {
  const env = (process.env["NUMASEC_BOOT"] || "").toLowerCase()
  if (env === "off" || env === "0" || env === "false") return false
  if (env === "force" || env === "always") return true
  try {
    await fs.access(sentinelPath())
    return false
  } catch {
    return true
  }
}

async function markSeen() {
  const p = sentinelPath()
  try {
    await fs.mkdir(path.dirname(p), { recursive: true })
    await fs.writeFile(p, new Date().toISOString() + "\n", { flag: "w" })
  } catch {}
}

export function BootSplash() {
  const { theme } = useTheme()
  const [active, setActive] = createSignal(false)
  const [tick, setTick] = createSignal(0)
  const [done, setDone] = createSignal(false)
  let interval: NodeJS.Timeout | undefined
  let finish: NodeJS.Timeout | undefined

  onMount(async () => {
    if (!(await shouldShow())) return
    setActive(true)
    interval = setInterval(() => setTick((t) => t + 1), FRAME_MS)
    finish = setTimeout(() => {
      setDone(true)
      if (interval) clearInterval(interval)
      setTimeout(() => setActive(false), FADE_MS)
      void markSeen()
    }, FRAMES * FRAME_MS + HOLD_MS).unref?.()
  })

  onCleanup(() => {
    if (interval) clearInterval(interval)
    if (finish) clearTimeout(finish)
  })

  createEffect(() => {
    void TOTAL_MS
  })

  return (
    <Show when={active()}>
      <box
        position="absolute"
        zIndex={9999}
        left={0}
        right={0}
        top={0}
        bottom={0}
        backgroundColor={theme.background}
        justifyContent="center"
        alignItems="center"
      >
        <box flexDirection="column" alignItems="center" gap={1}>
          {TARGET_LINES.map((line) => {
            const progress = done() ? 1 : Math.min(1, tick() / FRAMES)
            const rendered = done() ? line : noiseLine(line, progress)
            return (
              <text fg={done() ? theme.primary : theme.warning}>
                {rendered}
              </text>
            )
          })}
        </box>
      </box>
    </Show>
  )
}
