const ACTIONS = new Map<string, string>([
  ["add", "added"],
  ["approve", "approved"],
  ["claim", "claimed"],
  ["change", "changed"],
  ["close", "closed"],
  ["complete", "completed"],
  ["create", "created"],
  ["delete", "deleted"],
  ["disable", "disabled"],
  ["enable", "enabled"],
  ["publish", "published"],
  ["remove", "removed"],
  ["save", "saved"],
  ["send", "sent"],
  ["submit", "submitted"],
  ["update", "updated"],
  ["verify", "verified"],
  ["activate", "active"],
  ["archive", "archived"],
])

function lower(input: string) {
  return input.trim().toLowerCase()
}

function words(input: string) {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .split(" ")
    .map((item) => item.trim())
    .filter(Boolean)
}

export function inferActionKind(url: string, label?: string) {
  try {
    const value = new URL(url)
    const parts = value.pathname
      .split("/")
      .map((item) => lower(item))
      .filter(Boolean)
    let index = parts.length - 1
    while (index >= 0) {
      const item = parts[index] ?? ""
      if (ACTIONS.has(item)) return item
      index -= 1
    }
  } catch {}
  if (!label) return ""
  for (const item of words(label)) {
    if (ACTIONS.has(item)) return item
  }
  return ""
}

export function actionTarget(kind: string) {
  return ACTIONS.get(lower(kind)) ?? ""
}

export function inferActionResourceUrl(url: string, kind: string) {
  const name = lower(kind)
  if (!name) return ""
  try {
    const value = new URL(url)
    const parts = value.pathname.split("/").filter(Boolean)
    if (parts.length < 2) return ""
    const tail = lower(parts[parts.length - 1] ?? "")
    if (tail !== name) return ""
    parts.pop()
    value.pathname = `/${parts.join("/")}`
    value.search = ""
    value.hash = ""
    return value.toString()
  } catch {
    return ""
  }
}
