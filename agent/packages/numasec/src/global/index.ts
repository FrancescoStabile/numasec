import fs from "fs/promises"
import { xdgData, xdgCache, xdgConfig, xdgState } from "xdg-basedir"
import path from "path"
import os from "os"
import { Filesystem } from "../util/filesystem"

const app = "numasec"

const data = path.join(xdgData!, app)
const cache = path.join(xdgCache!, app)
const config = path.join(xdgConfig!, app)
const state = path.join(xdgState!, app)

export namespace Global {
  export const Path = {
    // Allow override via NUMASEC_TEST_HOME for test isolation
    get home() {
      return process.env.NUMASEC_TEST_HOME || os.homedir()
    },
    data,
    bin: path.join(cache, "bin"),
    log: path.join(data, "log"),
    cache,
    config,
    state,
  }
}

async function ensureDirectory(path: string, mode: number) {
  await fs.mkdir(path, { recursive: true, mode })
  if (process.platform === "win32") return
  await fs.chmod(path, mode)
}

await Promise.all([
  ensureDirectory(Global.Path.data, 0o700),
  ensureDirectory(Global.Path.config, 0o700),
  ensureDirectory(Global.Path.state, 0o700),
  ensureDirectory(Global.Path.log, 0o700),
  ensureDirectory(Global.Path.cache, 0o700),
  ensureDirectory(Global.Path.bin, 0o700),
])

const CACHE_VERSION = "21"

const version = await Filesystem.readText(path.join(Global.Path.cache, "version")).catch(() => "0")

if (version !== CACHE_VERSION) {
  try {
    const contents = await fs.readdir(Global.Path.cache)
    await Promise.all(
      contents.map((item) =>
        fs.rm(path.join(Global.Path.cache, item), {
          recursive: true,
          force: true,
        }),
      ),
    )
  } catch (e) {}
  await Filesystem.write(path.join(Global.Path.cache, "version"), CACHE_VERSION)
}
