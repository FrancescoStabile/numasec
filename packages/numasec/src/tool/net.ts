import z from "zod"
import { Effect } from "effect"
import * as net from "node:net"
import * as dgram from "node:dgram"
import * as Tool from "./tool"
import DESCRIPTION from "./net.txt"

const parameters = z.object({
  op: z.enum(["tcp_send", "udp_send", "banner_grab"]),
  host: z.string(),
  port: z.number().int().min(1).max(65535),
  payload: z.string().optional(),
  payload_encoding: z.enum(["utf8", "hex", "base64"]).optional(),
  timeout_ms: z.number().int().min(100).max(30000).optional(),
  read_bytes: z.number().int().min(1).max(1048576).optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { op: string; host: string; port: number; bytes_read: number }

function formatBytes(buf: Buffer) {
  let out = ""
  for (const byte of buf) {
    if (byte === 0x0a || byte === 0x0d || byte === 0x09 || (byte >= 0x20 && byte <= 0x7e)) {
      out += String.fromCharCode(byte)
    } else {
      out += `\\x${byte.toString(16).padStart(2, "0")}`
    }
  }
  return out
}

function encodePayload(p: Params): Buffer {
  if (!p.payload) return Buffer.alloc(0)
  return Buffer.from(p.payload, p.payload_encoding ?? "utf8")
}

function tcpSend(p: Params): Promise<Buffer> {
  const timeout = p.timeout_ms ?? 5000
  const readLimit = p.read_bytes ?? 16384
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let received = 0
    const socket = net.createConnection({ host: p.host, port: p.port, timeout })
    const finish = (err?: Error) => {
      socket.removeAllListeners()
      socket.destroy()
      if (err) reject(err)
      else resolve(Buffer.concat(chunks))
    }
    socket.once("connect", () => {
      const payload = encodePayload(p)
      if (payload.length) socket.write(payload)
    })
    socket.on("data", (d) => {
      chunks.push(d)
      received += d.length
      if (received >= readLimit) finish()
    })
    socket.once("end", () => finish())
    socket.once("close", () => finish())
    socket.once("timeout", () => finish())
    socket.once("error", (e) => finish(e))
  })
}

function udpSend(p: Params): Promise<Buffer> {
  const timeout = p.timeout_ms ?? 5000
  const readLimit = p.read_bytes ?? 16384
  const payload = encodePayload(p)
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let received = 0
    const sock = dgram.createSocket("udp4")
    const timer = setTimeout(() => {
      sock.close()
      resolve(Buffer.concat(chunks))
    }, timeout)
    sock.on("message", (msg) => {
      chunks.push(msg)
      received += msg.length
      if (received >= readLimit) {
        clearTimeout(timer)
        sock.close()
        resolve(Buffer.concat(chunks))
      }
    })
    sock.on("error", (e) => {
      clearTimeout(timer)
      sock.close()
      reject(e)
    })
    sock.send(payload, p.port, p.host, (err) => {
      if (err) {
        clearTimeout(timer)
        sock.close()
        reject(err)
      }
    })
  })
}

export const NetTool = Tool.define<typeof parameters, Metadata, never>(
  "net",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "net",
            patterns: [`${params.op}:${params.host}:${params.port}`],
            always: ["*"],
            metadata: {
              op: params.op,
              host: params.host,
              port: params.port,
            },
          })
          const buf = yield* Effect.tryPromise({
            try: () => (params.op === "udp_send" ? udpSend(params) : tcpSend(params)),
            catch: (e) => new Error(`net: ${(e as Error).message}`),
          })
          return {
            title: `${params.op} ${params.host}:${params.port}`,
            output: formatBytes(buf),
            metadata: { op: params.op, host: params.host, port: params.port, bytes_read: buf.length },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
