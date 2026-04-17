import { beforeEach, describe, expect, test } from "bun:test"

const src = await Bun.file(new URL("../public/theme-preload.js", import.meta.url)).text()

const run = () => Function(src)()

beforeEach(() => {
  document.head.innerHTML = ""
  document.documentElement.removeAttribute("data-theme")
  document.documentElement.removeAttribute("data-color-scheme")
  localStorage.clear()
  Object.defineProperty(window, "matchMedia", {
    value: () =>
      ({
        matches: false,
      }) as MediaQueryList,
    configurable: true,
  })
})

describe("theme preload", () => {
  test("migrates legacy oc-1 to default before mount", () => {
    localStorage.setItem("numasec-theme-id", "oc-1")
    localStorage.setItem("numasec-theme-css-light", "--background-base:#fff;")
    localStorage.setItem("numasec-theme-css-dark", "--background-base:#000;")

    run()

    expect(document.documentElement.dataset.theme).toBe("default")
    expect(document.documentElement.dataset.colorScheme).toBe("light")
    expect(localStorage.getItem("numasec-theme-id")).toBe("default")
    expect(localStorage.getItem("numasec-theme-css-light")).toBeNull()
    expect(localStorage.getItem("numasec-theme-css-dark")).toBeNull()
    expect(document.getElementById("numasec-theme-preload")).toBeNull()
  })

  test("keeps cached css for non-default themes", () => {
    localStorage.setItem("numasec-theme-id", "nightowl")
    localStorage.setItem("numasec-theme-css-light", "--background-base:#fff;")

    run()

    expect(document.documentElement.dataset.theme).toBe("nightowl")
    expect(document.getElementById("numasec-theme-preload")?.textContent).toContain("--background-base:#fff;")
  })
})
