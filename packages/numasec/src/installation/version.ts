declare global {
  const NUMASEC_VERSION: string
  const NUMASEC_CHANNEL: string
}

export const InstallationVersion = typeof NUMASEC_VERSION === "string" ? NUMASEC_VERSION : "local"
export const InstallationChannel = typeof NUMASEC_CHANNEL === "string" ? NUMASEC_CHANNEL : "local"
export const InstallationLocal = InstallationVersion === "local"
