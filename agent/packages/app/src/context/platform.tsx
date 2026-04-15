import { createSimpleContext } from "@numasec/ui/context"
import { ServerConnection } from "./server"

type PickerPaths = string | string[] | null
type OpenDirectoryPickerOptions = { title?: string; multiple?: boolean }
type OpenFilePickerOptions = { title?: string; multiple?: boolean; accept?: string[]; extensions?: string[] }

export type Platform = {
  /** Platform discriminator */
  platform: "web"

  /** App version */
  version?: string

  /** Open a URL in the default browser */
  openLink(url: string): void

  /** Restart the app */
  restart(): Promise<void>

  /** Navigate back in history */
  back(): void

  /** Navigate forward in history */
  forward(): void

  /** Send a system notification (optional deep link) */
  notify(title: string, description?: string, href?: string): Promise<void>

  /** Open directory picker dialog (server-backed) */
  openDirectoryPickerDialog?(opts?: OpenDirectoryPickerOptions): Promise<PickerPaths>

  /** Open file picker dialog */
  openFilePickerDialog?(opts?: OpenFilePickerOptions): Promise<PickerPaths>

  /** Fetch override */
  fetch?: typeof fetch

  /** Get the configured default server URL */
  getDefaultServer?(): Promise<ServerConnection.Key | null>

  /** Set the default server URL to use on app startup */
  setDefaultServer?(url: ServerConnection.Key | null): Promise<void> | void

  /** Read image from clipboard */
  readClipboardImage?(): Promise<File | null>
}

export const { use: usePlatform, provider: PlatformProvider } = createSimpleContext({
  name: "Platform",
  init: (props: { value: Platform }) => {
    return props.value
  },
})
