export * from "./client.js"
export * from "./server.js"

import { createNumasecClient } from "./client.js"
import { createNumasecServer } from "./server.js"
import type { ServerOptions } from "./server.js"

export async function createNumasec(options?: ServerOptions) {
  const server = await createNumasecServer({
    ...options,
  })

  const client = createNumasecClient({
    baseUrl: server.url,
  })

  return {
    client,
    server,
  }
}
