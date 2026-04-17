#!/usr/bin/env bun
import { $ } from "bun"
import pkg from "../package.json"
import { Script } from "@numasec/script"
import { fileURLToPath } from "url"

const dir = fileURLToPath(new URL("..", import.meta.url))
process.chdir(dir)

const binaries: Record<string, string> = {}
for (const filepath of new Bun.Glob("*/package.json").scanSync({ cwd: "./dist" })) {
  const pkg = await Bun.file(`./dist/${filepath}`).json()
  binaries[pkg.name] = pkg.version
}
console.log("binaries", binaries)
const version = Object.values(binaries)[0]

await $`mkdir -p ./dist/${pkg.name}`
await $`cp -r ./bin ./dist/${pkg.name}/bin`
await $`cp ./script/postinstall.mjs ./dist/${pkg.name}/postinstall.mjs`
await Bun.file(`./dist/${pkg.name}/LICENSE`).write(await Bun.file("../../LICENSE").text())

await Bun.file(`./dist/${pkg.name}/package.json`).write(
  JSON.stringify(
    {
      name: pkg.name + "-ai",
      bin: {
        [pkg.name]: `./bin/${pkg.name}`,
      },
      scripts: {
        postinstall: "bun ./postinstall.mjs || node ./postinstall.mjs",
      },
      version: version,
      license: pkg.license,
      optionalDependencies: binaries,
    },
    null,
    2,
  ),
)

const tasks = Object.entries(binaries).map(async ([name]) => {
  if (process.platform !== "win32") {
    await $`chmod -R 755 .`.cwd(`./dist/${name}`)
  }
  await $`bun pm pack`.cwd(`./dist/${name}`)
  await $`npm publish *.tgz --access public --tag ${Script.channel}`.cwd(`./dist/${name}`)
})
await Promise.all(tasks)
await $`cd ./dist/${pkg.name} && bun pm pack && npm publish *.tgz --access public --tag ${Script.channel}`

const image = "ghcr.io/francescostabile/numasec"
const platforms = "linux/amd64,linux/arm64"
const tags = [`${image}:${version}`, `${image}:${Script.channel}`]
const tagFlags = tags.flatMap((t) => ["-t", t])
await $`docker buildx build --platform ${platforms} ${tagFlags} --push .`

  // registries
  if (!Script.preview) {
    // Calculate SHA values
    const arm64Sha = await $`sha256sum ./dist/numasec-linux-arm64.tar.gz | cut -d' ' -f1`.text().then((x) => x.trim())
    const x64Sha = await $`sha256sum ./dist/numasec-linux-x64.tar.gz | cut -d' ' -f1`.text().then((x) => x.trim())

    const [pkgver, _subver = ""] = Script.version.split(/(-.*)/, 2)

  // arch
  const binaryPkgbuild = [
    "# Maintainer: dax",
    "# Maintainer: adam",
    "",
    "pkgname='numasec-bin'",
    `pkgver=${pkgver}`,
    `_subver=${_subver}`,
    "options=('!debug' '!strip')",
    "pkgrel=1",
    "pkgdesc='AI-powered penetration testing platform for the terminal.'",
    "url='https://github.com/FrancescoStabile/numasec'",
    "arch=('aarch64' 'x86_64')",
    "license=('MIT')",
    "provides=('numasec')",
    "conflicts=('numasec')",
    "depends=('ripgrep')",
    "",
    `source_aarch64=("\${pkgname}_\${pkgver}_aarch64.tar.gz::https://github.com/FrancescoStabile/numasec/releases/download/v\${pkgver}\${_subver}/numasec-linux-arm64.tar.gz")`,
    `sha256sums_aarch64=('${arm64Sha}')`,

    `source_x86_64=("\${pkgname}_\${pkgver}_x86_64.tar.gz::https://github.com/FrancescoStabile/numasec/releases/download/v\${pkgver}\${_subver}/numasec-linux-x64.tar.gz")`,
    `sha256sums_x86_64=('${x64Sha}')`,
    "",
    "package() {",
    '  install -Dm755 ./numasec "${pkgdir}/usr/bin/numasec"',
    "}",
    "",
  ].join("\n")

  for (const [pkg, pkgbuild] of [["numasec-bin", binaryPkgbuild]]) {
    for (let i = 0; i < 30; i++) {
      try {
        await $`rm -rf ./dist/aur-${pkg}`
        await $`git clone ssh://aur@aur.archlinux.org/${pkg}.git ./dist/aur-${pkg}`
        await $`cd ./dist/aur-${pkg} && git checkout master`
        await Bun.file(`./dist/aur-${pkg}/PKGBUILD`).write(pkgbuild)
        await $`cd ./dist/aur-${pkg} && makepkg --printsrcinfo > .SRCINFO`
        await $`cd ./dist/aur-${pkg} && git add PKGBUILD .SRCINFO`
        await $`cd ./dist/aur-${pkg} && git commit -m "Update to v${Script.version}"`
        await $`cd ./dist/aur-${pkg} && git push`
        break
      } catch (e) {
        continue
      }
    }
  }
}
