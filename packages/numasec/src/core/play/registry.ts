import type { Play } from "./play"
import webSurface from "./data/web-surface"
import networkSurface from "./data/network-surface"
import appsecTriage from "./data/appsec-triage"
import osintTarget from "./data/osint-target"
import ctfWarmup from "./data/ctf-warmup"
import apiSurface from "./data/api-surface"
import authSurface from "./data/auth-surface"
import cloudPosture from "./data/cloud-posture"
import containerSurface from "./data/container-surface"
import iacTriage from "./data/iac-triage"
import binaryTriage from "./data/binary-triage"

const plays: Record<string, Play> = {
  [webSurface.id]: webSurface,
  [networkSurface.id]: networkSurface,
  [appsecTriage.id]: appsecTriage,
  [osintTarget.id]: osintTarget,
  [ctfWarmup.id]: ctfWarmup,
  [apiSurface.id]: apiSurface,
  [authSurface.id]: authSurface,
  [cloudPosture.id]: cloudPosture,
  [containerSurface.id]: containerSurface,
  [iacTriage.id]: iacTriage,
  [binaryTriage.id]: binaryTriage,
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
