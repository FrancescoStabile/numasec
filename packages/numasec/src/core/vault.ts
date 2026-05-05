import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

export type VaultEntry = { value: string; updated_at: string }

export type VaultState = {
  secrets: Record<string, VaultEntry>
  active_identity: string | null
  active_identity_set_at: string | null
}

export type ResolvedIdentity = {
  key: string
  mode: "headers" | "cookies" | "bearer"
  headers?: Record<string, string>
  cookies?: string
}

const EMPTY_VAULT: VaultState = { secrets: {}, active_identity: null, active_identity_set_at: null }

export function configDir() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  return path.join(base, "numasec")
}

export function vaultPath() {
  return path.join(configDir(), "vault.json")
}

export async function loadVault(): Promise<VaultState> {
  try {
    const text = await fs.readFile(vaultPath(), "utf-8")
    const parsed = JSON.parse(text) as Partial<VaultState>
    return {
      secrets: parsed.secrets ?? {},
      active_identity: parsed.active_identity ?? null,
      active_identity_set_at: parsed.active_identity_set_at ?? null,
    }
  } catch {
    return { ...EMPTY_VAULT, secrets: {} }
  }
}

export async function saveVault(vault: VaultState) {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 })
  const file = vaultPath()
  await fs.writeFile(file, JSON.stringify(vault, null, 2), { mode: 0o600 })
  await fs.chmod(file, 0o600)
}

function cookieLike(value: string) {
  return value.includes("=") && value.split(";").every((item) => item.trim().includes("="))
}

export function resolveIdentityValue(key: string, value: string): ResolvedIdentity {
  try {
    const parsed = JSON.parse(value) as {
      headers?: Record<string, string>
      cookies?: string
      cookie?: string
      authorization?: string
      bearer?: string
    }
    const headers = typeof parsed.headers === "object" && parsed.headers ? parsed.headers : undefined
    const cookies = typeof parsed.cookies === "string" ? parsed.cookies : typeof parsed.cookie === "string" ? parsed.cookie : undefined
    if (headers || cookies) {
      return {
        key,
        mode: headers ? "headers" : "cookies",
        headers: {
          ...(headers ?? {}),
          ...(typeof parsed.authorization === "string" ? { Authorization: parsed.authorization } : {}),
          ...(typeof parsed.bearer === "string" ? { Authorization: `Bearer ${parsed.bearer}` } : {}),
        },
        cookies,
      }
    }
  } catch {}

  if (value.startsWith("Authorization:")) {
    return {
      key,
      mode: "headers",
      headers: { Authorization: value.slice("Authorization:".length).trim() },
    }
  }

  if (value.startsWith("Cookie:")) {
    return {
      key,
      mode: "cookies",
      cookies: value.slice("Cookie:".length).trim(),
    }
  }

  if (value.startsWith("Bearer ")) {
    return {
      key,
      mode: "bearer",
      headers: { Authorization: value },
    }
  }

  if (cookieLike(value)) {
    return {
      key,
      mode: "cookies",
      cookies: value,
    }
  }

  return {
    key,
    mode: "bearer",
    headers: { Authorization: `Bearer ${value}` },
  }
}

export async function activeIdentity() {
  const vault = await loadVault()
  if (!vault.active_identity) return undefined
  const entry = vault.secrets[vault.active_identity]
  if (!entry) return undefined
  return resolveIdentityValue(vault.active_identity, entry.value)
}
