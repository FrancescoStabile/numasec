import type { Play } from "./play"
import webSurface from "./data/web-surface"
import networkSurface from "./data/network-surface"
import appsecTriage from "./data/appsec-triage"
import osintTarget from "./data/osint-target"
import ctfWarmup from "./data/ctf-warmup"

const plays: Record<string, Play> = {
  [webSurface.id]: webSurface,
  [networkSurface.id]: networkSurface,
  [appsecTriage.id]: appsecTriage,
  [osintTarget.id]: osintTarget,
  [ctfWarmup.id]: ctfWarmup,
}

export namespace PlayRegistry {
  export function list(): Play[] {
    return Object.values(plays)
  }

  export function get(id: string): Play | undefined {
    return plays[id]
  }

  export function ids(): string[] {
    return Object.keys(plays)
  }
}
