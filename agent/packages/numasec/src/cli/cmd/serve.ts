import { Server } from "../../server/server"
import { cmd } from "./cmd"
import { withNetworkOptions, resolveNetworkOptions } from "../network"
import { Workspace } from "../../control-plane/workspace"
import { Project } from "../../project/project"
import { Installation } from "../../installation"
import { Instance } from "../../project/instance"

export const ServeCommand = cmd({
  command: "serve",
  builder: (yargs) => withNetworkOptions(yargs),
  describe: "starts a headless numasec server",
  handler: async (args) => {
    const opts = await resolveNetworkOptions(args)
    // Security tools are now native TypeScript — no Python bridge needed
    await Instance.provide({
      directory: process.cwd(),
      fn: async () => {},
    })
    const server = Server.listen(opts)
    if (server.auth) {
      console.log(`numasec server auth enabled for user ${server.auth.username}`)
    }
    if (!server.auth && server.authPolicy.explicitInsecureNoAuth) {
      console.log("Warning: external server auth explicitly disabled via NUMASEC_SERVER_INSECURE_NO_AUTH=1")
    }
    console.log(`numasec server listening on http://${server.hostname}:${server.port}`)

    await new Promise(() => {})
    await server.stop()
  },
})
