import { readFileSync } from "node:fs"
import solidPlugin from "vite-plugin-solid"
import tailwindcss from "@tailwindcss/vite"
import { fileURLToPath } from "url"

const theme = fileURLToPath(new URL("./public/theme-preload.js", import.meta.url))

/**
 * @type {import("vite").PluginOption}
 */
export default [
  {
    name: "numasec-desktop:config",
    config() {
      return {
        resolve: {
          alias: {
            "@": fileURLToPath(new URL("./src", import.meta.url)),
          },
        },
        worker: {
          format: "es",
        },
      }
    },
  },
  {
    name: "numasec-desktop:theme-preload",
    transformIndexHtml(html) {
      return html.replace(
        '<script id="numasec-theme-preload-script" src="/theme-preload.js"></script>',
        `<script id="numasec-theme-preload-script">${readFileSync(theme, "utf8")}</script>`,
      )
    },
  },
  tailwindcss(),
  solidPlugin(),
]
