/**
 * Scanner: port scanner
 *
 * Pure TypeScript TCP port scanner using Node's net.connect with
 * banner grabbing for service identification.
 */

import { connect } from "net"

export interface PortResult {
  port: number
  open: boolean
  service?: string
  version?: string
  elapsed: number
}

export interface PortScanResult {
  host: string
  openPorts: PortResult[]
  closedCount: number
  elapsed: number
}

const TOP_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
  9090, 9200, 9300, 27017,
]

const SERVICE_SIGNATURES: [RegExp, string][] = [
  [/^SSH-/, "ssh"],
  [/^220.*FTP/i, "ftp"],
  [/^220.*SMTP/i, "smtp"],
  [/^\* OK.*IMAP/i, "imap"],
  [/^\+OK.*POP3/i, "pop3"],
  [/^HTTP\//, "http"],
  [/^{.*"/, "json-api"],
  [/<html/i, "http"],
  [/^MySQL/, "mysql"],
  [/^PostgreSQL/, "postgresql"],
  [/ERR.*Redis/, "redis"],
  [/MongoDB/, "mongodb"],
]

function identifyService(banner: string): string | undefined {
  for (const [re, name] of SERVICE_SIGNATURES) {
    if (re.test(banner)) return name
  }
  return undefined
}

function probePort(host: string, port: number, timeout: number): Promise<PortResult> {
  const start = Date.now()
  return new Promise((resolve) => {
    const socket = connect({ host, port, timeout }, () => {
      socket.setTimeout(2000)

      socket.once("data", (data) => {
        const banner = data.toString("utf-8").trim()
        socket.destroy()
        resolve({
          port,
          open: true,
          service: identifyService(banner),
          version: banner.slice(0, 100),
          elapsed: Date.now() - start,
        })
      })

      socket.once("timeout", () => {
        socket.destroy()
        resolve({ port, open: true, elapsed: Date.now() - start })
      })
    })

    socket.on("error", () => {
      socket.destroy()
      resolve({ port, open: false, elapsed: Date.now() - start })
    })

    socket.on("timeout", () => {
      socket.destroy()
      resolve({ port, open: false, elapsed: Date.now() - start })
    })
  })
}

/**
 * Scan ports on a host. Pure TypeScript — no external tools required.
 */
export async function scanPorts(
  host: string,
  options: { ports?: number[]; concurrency?: number; timeout?: number } = {},
): Promise<PortScanResult> {
  const ports = options.ports ?? TOP_PORTS
  const concurrency = options.concurrency ?? 50
  const timeout = options.timeout ?? 3000
  const start = Date.now()
  const results: PortResult[] = []
  let closed = 0

  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency)
    const batchResults = await Promise.all(batch.map((p) => probePort(host, p, timeout)))
    for (const r of batchResults) {
      if (r.open) results.push(r)
      else closed++
    }
  }

  return {
    host,
    openPorts: results.sort((a, b) => a.port - b.port),
    closedCount: closed,
    elapsed: Date.now() - start,
  }
}
