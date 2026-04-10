/**
 * BM25 retriever with contextual header prepend (400–512 token chunks).
 *
 * Port of Python numasec.knowledge.retriever. BM25Okapi implemented from
 * scratch (no external dependency). Optional hybrid semantic reranking
 * is stubbed but not wired — BM25-only is sufficient for KB size.
 *
 * Inspired by Anthropic Contextual Retrieval: -49% retrieval failures.
 */

import type { KBTemplate } from "./loader"

// ── Chunk ──────────────────────────────────────────────────────

export interface Chunk {
  text: string
  section: string
  templateId: string
  category: string
  score: number
  metadata: Record<string, unknown>
}

// ── Chunker ────────────────────────────────────────────────────

const MAX_TOKENS = 450
const OVERLAP_TOKENS = 60

function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4)
}

/** Split a template into chunks with contextual headers. */
export function chunkTemplate(template: KBTemplate): Chunk[] {
  const templateId = template.id
  const category = template.category ?? ""
  const title = template.title ?? templateId
  const chunks: Chunk[] = []

  const sections = splitSections(template)
  for (const [sectionName, sectionText] of sections) {
    const header = `[${category}] ${title} > ${sectionName}\n`
    const pieces = splitPreservingBoundaries(sectionText)
    for (const piece of pieces) {
      const fullText = header + piece
      if (estimateTokens(fullText) > 0) {
        chunks.push({
          text: fullText,
          section: sectionName,
          templateId,
          category,
          score: 0,
          metadata: {},
        })
      }
    }
  }

  return chunks
}

const SKIP_KEYS = new Set(["id", "category", "title", "version", "tags", "cwe_ids"])

function splitSections(template: KBTemplate): [string, string][] {
  const sections: [string, string][] = []
  for (const [key, value] of Object.entries(template)) {
    if (SKIP_KEYS.has(key)) continue
    if (typeof value === "string") {
      sections.push([key, value])
    } else if (Array.isArray(value)) {
      sections.push([key, value.map(String).join("\n")])
    } else if (value && typeof value === "object") {
      const lines: string[] = []
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (Array.isArray(v)) {
          lines.push(`${k}:`)
          for (const item of v) lines.push(`  - ${item}`)
        } else {
          lines.push(`${k}: ${v}`)
        }
      }
      sections.push([key, lines.join("\n")])
    }
  }
  return sections
}

function splitPreservingBoundaries(text: string): string[] {
  const maxChars = MAX_TOKENS * 4
  const overlapChars = OVERLAP_TOKENS * 4

  if (text.length <= maxChars) return text.trim() ? [text] : []

  const pieces: string[] = []
  const lines = text.split("\n")
  let current: string[] = []
  let currentLen = 0
  let inCodeBlock = false

  for (const line of lines) {
    const lineLen = line.length + 1

    if (line.trim().startsWith("```")) inCodeBlock = !inCodeBlock

    if (currentLen + lineLen > maxChars && !inCodeBlock && current.length > 0) {
      pieces.push(current.join("\n"))
      // Overlap: keep last few lines
      const overlap: string[] = []
      let overlapLen = 0
      for (let i = current.length - 1; i >= 0; i--) {
        if (overlapLen + current[i].length + 1 > overlapChars) break
        overlap.unshift(current[i])
        overlapLen += current[i].length + 1
      }
      current = overlap
      currentLen = overlapLen
    }

    current.push(line)
    currentLen += lineLen
  }

  if (current.length > 0) pieces.push(current.join("\n"))
  return pieces
}

// ── BM25Okapi ──────────────────────────────────────────────────

function tokenize(text: string): string[] {
  return text.toLowerCase().match(/\w+/g) ?? []
}

/**
 * BM25Okapi implementation (no external dependency).
 * Standard parameters: k1=1.5, b=0.75.
 */
class BM25Index {
  private readonly k1 = 1.5
  private readonly b = 0.75
  private readonly corpus: string[][]
  private readonly docLengths: number[]
  private readonly avgDl: number
  private readonly df: Map<string, number>
  private readonly idf: Map<string, number>
  private readonly N: number

  constructor(corpus: string[][]) {
    this.corpus = corpus
    this.N = corpus.length
    this.docLengths = corpus.map((doc) => doc.length)
    this.avgDl = this.docLengths.reduce((a, b) => a + b, 0) / (this.N || 1)

    // Document frequency
    this.df = new Map()
    for (const doc of corpus) {
      const seen = new Set(doc)
      for (const term of seen) {
        this.df.set(term, (this.df.get(term) ?? 0) + 1)
      }
    }

    // IDF: log((N - df + 0.5) / (df + 0.5) + 1)
    this.idf = new Map()
    for (const [term, df] of this.df) {
      this.idf.set(term, Math.log((this.N - df + 0.5) / (df + 0.5) + 1))
    }
  }

  getScores(query: string[]): number[] {
    const scores = new Array<number>(this.N).fill(0)
    for (const term of query) {
      const idf = this.idf.get(term)
      if (idf === undefined) continue
      for (let i = 0; i < this.N; i++) {
        const tf = this.corpus[i].filter((t) => t === term).length
        const dl = this.docLengths[i]
        const numerator = tf * (this.k1 + 1)
        const denominator = tf + this.k1 * (1 - this.b + this.b * (dl / this.avgDl))
        scores[i] += idf * (numerator / denominator)
      }
    }
    return scores
  }
}

// ── Retriever ──────────────────────────────────────────────────

export class KnowledgeRetriever {
  private chunks: Chunk[] = []
  private index: BM25Index | undefined

  constructor(chunks?: Chunk[]) {
    if (chunks && chunks.length > 0) {
      this.chunks = chunks
      this.buildIndex()
    }
  }

  addChunks(newChunks: Chunk[]): void {
    this.chunks.push(...newChunks)
    this.buildIndex()
  }

  private buildIndex(): void {
    const corpus = this.chunks.map((c) => tokenize(c.text))
    this.index = new BM25Index(corpus)
  }

  /**
   * Query the knowledge base with BM25 scoring.
   * Supports category and CWE text filtering.
   */
  query(
    question: string,
    options: { topK?: number; category?: string; cwe?: string } = {},
  ): Chunk[] {
    const { topK = 5, category, cwe } = options
    if (this.chunks.length === 0 || !this.index) return []

    const tokens = tokenize(question)
    if (tokens.length === 0) return []

    const scores = this.index.getScores(tokens)

    // Pair chunks with scores, apply filters
    let scored: [number, number][] = scores.map((score, idx) => [score, idx])

    if (category) {
      scored = scored.filter(([, i]) => this.chunks[i].category === category)
    }
    if (cwe) {
      scored = scored.filter(([, i]) => this.chunks[i].text.includes(cwe))
    }

    // Sort descending
    scored.sort((a, b) => b[0] - a[0])

    // Take top-k with positive scores
    const results: Chunk[] = []
    for (const [score, idx] of scored.slice(0, topK)) {
      if (score <= 0) break
      const chunk = { ...this.chunks[idx], score }
      results.push(chunk)
    }

    return results
  }
}

/**
 * Build a retriever from a map of loaded templates.
 * Chunks all templates and indexes them for BM25 search.
 */
export function buildRetriever(templates: Map<string, KBTemplate>): KnowledgeRetriever {
  const allChunks: Chunk[] = []
  for (const template of templates.values()) {
    allChunks.push(...chunkTemplate(template))
  }
  return new KnowledgeRetriever(allChunks)
}
