/**
 * YAML template loader for the knowledge base.
 *
 * Loads bundled + user templates from disk. Each template must have an `id` field.
 */

import { readFileSync, readdirSync, statSync, existsSync } from "fs"
import { join, extname } from "path"
import { parse as parseYaml } from "yaml"

export interface KBTemplate {
  id: string
  title?: string
  category?: string
  version?: string
  tags?: string[]
  cwe_ids?: string[]
  [key: string]: unknown
}

// Bundled templates ship alongside this module
const BUNDLED_DIR = join(__dirname, "templates")

/**
 * Load all YAML templates from the given directories.
 * Includes bundled templates by default.
 */
export function loadTemplates(
  extraDirs: string[] = [],
  options: { includeBundled?: boolean } = {},
): Map<string, KBTemplate> {
  const { includeBundled = true } = options
  const templates = new Map<string, KBTemplate>()
  const dirs: string[] = []

  if (includeBundled && existsSync(BUNDLED_DIR)) {
    dirs.push(BUNDLED_DIR)
  }
  dirs.push(...extraDirs)

  for (const dir of dirs) {
    if (!existsSync(dir)) continue
    for (const file of walkYaml(dir)) {
      const template = loadSingleTemplate(file)
      if (template) templates.set(template.id, template)
    }
  }

  return templates
}

/** Recursively walk a directory and yield .yaml file paths. */
function walkYaml(dir: string): string[] {
  const results: string[] = []
  try {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      const stat = statSync(full)
      if (stat.isDirectory()) {
        results.push(...walkYaml(full))
      } else if (extname(entry) === ".yaml" || extname(entry) === ".yml") {
        results.push(full)
      }
    }
  } catch {
    // Skip unreadable directories
  }
  return results
}

/** Load and validate a single YAML template file. */
function loadSingleTemplate(path: string): KBTemplate | undefined {
  try {
    const content = readFileSync(path, "utf-8")
    const data = parseYaml(content)
    if (data && typeof data === "object" && "id" in data && typeof data.id === "string") {
      return data as KBTemplate
    }
  } catch {
    // Skip malformed templates
  }
  return undefined
}
