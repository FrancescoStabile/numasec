/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
  app(input) {
    return {
      name: "numasec",
      removal: input?.stage === "production" ? "retain" : "remove",
      protect: ["production"].includes(input?.stage),
      home: "cloudflare",
      providers: {
        stripe: {
          apiKey: process.env.STRIPE_SECRET_KEY!,
        },
        planetscale: "0.4.1",
      },
    }
  },
  async run() {
    // Console, web, and enterprise deployments shut down per PRD D3.
    // Source kept in infra/ for future re-deployment when content is rewritten for security.
    // await import("./infra/app.js")
    // await import("./infra/console.js")
    // await import("./infra/enterprise.js")
  },
})
