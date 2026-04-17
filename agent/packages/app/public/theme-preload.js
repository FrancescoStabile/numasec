;(function () {
  var key = "numasec-theme-id"
  var themeId = localStorage.getItem(key) || "default"

  if (themeId === "oc-1" || themeId === "oc-2") {
    themeId = "default"
    localStorage.setItem(key, themeId)
    localStorage.removeItem("numasec-theme-css-light")
    localStorage.removeItem("numasec-theme-css-dark")
  }

  var scheme = localStorage.getItem("numasec-color-scheme") || "system"
  var isDark = scheme === "dark" || (scheme === "system" && matchMedia("(prefers-color-scheme: dark)").matches)
  var mode = isDark ? "dark" : "light"

  document.documentElement.dataset.theme = themeId
  document.documentElement.dataset.colorScheme = mode

  if (themeId === "default") return

  var css = localStorage.getItem("numasec-theme-css-" + mode)
  if (css) {
    var style = document.createElement("style")
    style.id = "numasec-theme-preload"
    style.textContent =
      ":root{color-scheme:" +
      mode +
      ";--text-mix-blend-mode:" +
      (isDark ? "plus-lighter" : "multiply") +
      ";" +
      css +
      "}"
    document.head.appendChild(style)
  }
})()
