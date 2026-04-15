function digit(input: string) {
  return /^[0-9]+$/.test(input)
}

function tokens(input: string) {
  const out: string[] = []
  const items = input.replace(/\[(\d+)\]/g, ".$1").split(".")
  for (const item of items) {
    const key = item.trim()
    if (!key) continue
    out.push(key)
  }
  return out
}

function write(input: unknown, path: string[], value: unknown): unknown {
  const head = path[0]
  if (!head) return value
  const rest = path.slice(1)
  if (digit(head)) {
    const list = Array.isArray(input) ? [...input] : []
    list[Number(head)] = write(list[Number(head)], rest, value)
    return list
  }
  const map =
    input && typeof input === "object" && !Array.isArray(input)
      ? { ...(input as Record<string, unknown>) }
      : {}
  map[head] = write(map[head], rest, value)
  return map
}

export function assignJsonValue(input: unknown, path: string, value: unknown) {
  const list = tokens(path)
  if (list.length === 0) return value
  return write(input, list, value)
}

export function collectJsonLeafPaths(input: unknown, path = ""): string[] {
  if (input === null || typeof input !== "object") {
    if (!path) return []
    return [path]
  }
  if (Array.isArray(input)) {
    if (input.length === 0) return path ? [path] : []
    const out: string[] = []
    for (let i = 0; i < input.length; i++) {
      const next = path ? `${path}[${i}]` : `[${i}]`
      const nested = collectJsonLeafPaths(input[i], next)
      if (nested.length === 0) out.push(next)
      else out.push(...nested)
    }
    return out
  }
  const map = input as Record<string, unknown>
  const keys = Object.keys(map)
  if (keys.length === 0) return path ? [path] : []
  const out: string[] = []
  for (const key of keys) {
    const next = path ? `${path}.${key}` : key
    const nested = collectJsonLeafPaths(map[key], next)
    if (nested.length === 0) out.push(next)
    else out.push(...nested)
  }
  return out
}
