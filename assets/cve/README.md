# CVE Offline Bundle

Compact, offline-only CVE index consumed by the `cve` tool. The bundle is read
at runtime from `assets/cve/index.json.gz` — no network call is ever made at
runtime.

## Shape

Each entry in the decompressed JSON array has the shape:

```ts
{
  id: string          // e.g. "CVE-2021-44228"
  severity: "low" | "medium" | "high" | "critical"
  cvss: number        // CVSS v3 base score (0-10)
  summary: string     // first 280 chars of the NVD description
  cpe: string[]       // affected CPE 2.3 URIs (truncated)
  published: string   // ISO 8601
}
```

## Lifecycle

1. A **seed bundle** (≈10 famous CVEs) is committed to this directory so the
   `cve` tool works out-of-the-box on a fresh checkout. Seed it manually with:

   ```bash
   bun run packages/numasec/script/seed-cve.ts
   ```

2. The **refresh workflow** (`.github/workflows/cve-refresh.yml`) replaces the
   bundle weekly (cron `0 6 * * 1` UTC) by pulling NVD's `recent` and
   `modified` JSON feeds from
   <https://nvd.nist.gov/feeds/json/cve/1.1/>, merging them into the existing
   index, capping summaries at 280 chars, and gzipping the result.

3. The workflow opens a PR against `release/1.1.5` (or the current release
   branch) with the refreshed `index.json.gz`.

## Size budget

Target: **≤ 8 MB gzipped**. If the refresher ever overshoots the budget it
drops the oldest `informational`/`low` entries first.

## No secrets, no API keys

The NVD JSON feeds are anonymous, unauthenticated downloads. This bundle
intentionally does not consume the NVD REST API (which rate-limits without an
API key).
