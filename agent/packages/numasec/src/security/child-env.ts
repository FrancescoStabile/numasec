const KEYS = [
  "APPDATA",
  "COLORTERM",
  "COMSPEC",
  "HOME",
  "HOMEDRIVE",
  "HOMEPATH",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "LOCALAPPDATA",
  "LOGNAME",
  "NO_COLOR",
  "NO_PROXY",
  "PATH",
  "PATHEXT",
  "SHELL",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMROOT",
  "TEMP",
  "TERM",
  "TMP",
  "TMPDIR",
  "USER",
  "USERPROFILE",
  "WINDIR",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "http_proxy",
  "https_proxy",
  "no_proxy",
] as const

export function securityChildEnv(input: Record<string, string> = {}) {
  const next: Record<string, string> = {}
  for (const key of KEYS) {
    const value = process.env[key]
    if (value === undefined) continue
    next[key] = value
  }
  next.TERM = "dumb"
  return {
    ...next,
    ...input,
  }
}
