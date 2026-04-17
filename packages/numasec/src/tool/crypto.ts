import z from "zod"
import { Effect } from "effect"
import { createHash, createHmac } from "node:crypto"
import * as Tool from "./tool"
import DESCRIPTION from "./crypto.txt"

const parameters = z.object({
  op: z.enum(["hash", "hmac", "encode", "decode", "jwt_decode", "xor"]),
  algo: z.string().optional().describe("hash/hmac algo: sha256 (default), sha1, md5, sha512"),
  codec: z.enum(["base64", "base64url", "hex", "url", "rot13"]).optional(),
  data: z.string().optional(),
  key: z.string().optional(),
  token: z.string().optional(),
  encoding: z.enum(["hex", "base64", "base64url"]).optional().describe("output encoding for hash/hmac (default hex)"),
  input_encoding: z.enum(["utf8", "base64", "hex"]).optional().describe("how to interpret `data` (default utf8)"),
})

type Params = z.infer<typeof parameters>
type Metadata = { op: string; algo?: string; codec?: string }

function toBuf(value: string, enc: Params["input_encoding"]) {
  return Buffer.from(value, enc ?? "utf8")
}

function rot13(s: string) {
  return s.replace(/[A-Za-z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
  })
}

function run(p: Params): string {
  switch (p.op) {
    case "hash": {
      if (!p.data) throw new Error("hash requires data")
      const h = createHash(p.algo ?? "sha256").update(toBuf(p.data, p.input_encoding))
      return h.digest((p.encoding ?? "hex") as "hex" | "base64" | "base64url")
    }
    case "hmac": {
      if (!p.data || !p.key) throw new Error("hmac requires data and key")
      const h = createHmac(p.algo ?? "sha256", p.key).update(toBuf(p.data, p.input_encoding))
      return h.digest((p.encoding ?? "hex") as "hex" | "base64" | "base64url")
    }
    case "encode": {
      if (!p.codec || p.data === undefined) throw new Error("encode requires codec and data")
      if (p.codec === "rot13") return rot13(p.data)
      if (p.codec === "url") return encodeURIComponent(p.data)
      return Buffer.from(p.data, p.input_encoding ?? "utf8").toString(p.codec)
    }
    case "decode": {
      if (!p.codec || p.data === undefined) throw new Error("decode requires codec and data")
      if (p.codec === "rot13") return rot13(p.data)
      if (p.codec === "url") return decodeURIComponent(p.data)
      return Buffer.from(p.data, p.codec).toString("utf8")
    }
    case "jwt_decode": {
      if (!p.token) throw new Error("jwt_decode requires token")
      const parts = p.token.split(".")
      if (parts.length !== 3) throw new Error("token does not have 3 segments")
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"))
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
      const signature_hex = Buffer.from(parts[2], "base64url").toString("hex")
      return JSON.stringify({ header, payload, signature_hex }, null, 2)
    }
    case "xor": {
      if (!p.data || !p.key) throw new Error("xor requires data and key")
      const dataBuf = toBuf(p.data, p.input_encoding)
      const keyBuf = Buffer.from(p.key, "utf8")
      const out = Buffer.alloc(dataBuf.length)
      for (let i = 0; i < dataBuf.length; i++) out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length]
      return out.toString((p.encoding ?? "hex") as "hex" | "base64" | "base64url")
    }
  }
}

export const CryptoTool = Tool.define<typeof parameters, Metadata, never>(
  "crypto",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, _ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const output = yield* Effect.try({
            try: () => run(params),
            catch: (e) => new Error(`crypto: ${(e as Error).message}`),
          })
          return {
            title: `${params.op}${params.algo ? " " + params.algo : params.codec ? " " + params.codec : ""}`,
            output,
            metadata: { op: params.op, algo: params.algo, codec: params.codec },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
