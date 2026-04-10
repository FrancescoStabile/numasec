/**
 * Scanner: service prober
 *
 * Protocol detection on open ports. Sends protocol-specific probes
 * and identifies services by response patterns.
 */

import { connect } from "net"

export interface ServiceInfo {
  port: number
  protocol: string
  service: string
  version?: string
  banner?: string
  tls: boolean
}

export interface ServiceProbeResult {
  services: ServiceInfo[]
  elapsed: number
}

// Protocol probes: send bytes, match response
const PROBES: { name: string; probe: Buffer | string; match: RegExp; protocol: string }[] = [
  { name: "HTTP", probe: "GET / HTTP/1.1\r\nHost: target\r\n\r\n", match: /HTTP\/[12]/, protocol: "http" },
  { name: "SSH", probe: "", match: /^SSH-/, protocol: "ssh" },
  { name: "FTP", probe: "", match: /^220[\s-]/, protocol: "ftp" },
  { name: "SMTP", probe: "", match: /^220.*(?:SMTP|mail)/i, protocol: "smtp" },
  { name: "POP3", probe: "", match: /^\+OK/i, protocol: "pop3" },
  { name: "IMAP", probe: "", match: /^\* OK.*IMAP/i, protocol: "imap" },
  { name: "MySQL", probe: "", match: /mysql|MariaDB/i, protocol: "mysql" },
  { name: "PostgreSQL", probe: "", match: /PostgreSQL|invalid length of startup packet/i, protocol: "postgresql" },
  { name: "Redis", probe: "PING\r\n", match: /^\+PONG|-ERR|-NOAUTH/i, protocol: "redis" },
  { name: "MongoDB", probe: "", match: /MongoDB|ismaster/i, protocol: "mongodb" },
  { name: "Memcached", probe: "version\r\n", match: /^VERSION /i, protocol: "memcached" },
  { name: "RDP", probe: "", match: /^\x03\x00/, protocol: "rdp" },
]

function probeService(host: string, port: number, timeout: number): Promise<ServiceInfo | null> {
  return new Promise((resolve) => {
    let identified = false

    const socket = connect({ host, port, timeout }, () => {
      // Try each probe
      const tryProbes = async () => {
        // First, wait for spontaneous banner
        socket.setTimeout(2000)
        socket.once("data", (data) => {
          if (identified) return
          const banner = data.toString("utf-8").trim()

          for (const probe of PROBES) {
            if (probe.match.test(banner)) {
              identified = true
              socket.destroy()
              resolve({
                port,
                protocol: probe.protocol,
                service: probe.name,
                banner: banner.slice(0, 200),
                tls: false,
              })
              return
            }
          }

          // Unknown service with banner
          socket.destroy()
          resolve({
            port,
            protocol: "unknown",
            service: "unknown",
            banner: banner.slice(0, 200),
            tls: false,
          })
        })

        socket.once("timeout", () => {
          if (identified) return
          // No spontaneous banner — try active probes
          for (const probe of PROBES) {
            if (probe.probe) {
              socket.write(probe.probe)
              break
            }
          }
          // Give it a moment more
          setTimeout(() => {
            if (!identified) {
              socket.destroy()
              resolve({ port, protocol: "unknown", service: "filtered", tls: false })
            }
          }, 2000)
        })
      }

      tryProbes()
    })

    socket.on("error", () => {
      socket.destroy()
      resolve(null)
    })

    socket.on("timeout", () => {
      socket.destroy()
      if (!identified) resolve(null)
    })
  })
}

/**
 * Probe services on specified ports.
 */
export async function probeServices(
  host: string,
  ports: number[],
  options: { concurrency?: number; timeout?: number } = {},
): Promise<ServiceProbeResult> {
  const { concurrency = 10, timeout = 5000 } = options
  const start = Date.now()
  const services: ServiceInfo[] = []

  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency)
    const results = await Promise.all(batch.map((p) => probeService(host, p, timeout)))
    for (const r of results) {
      if (r) services.push(r)
    }
  }

  return { services, elapsed: Date.now() - start }
}
