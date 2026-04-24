# numasec Plugins

numasec is extensible. The built in palette is intentionally broad, but not
meant to be the last word.

Plugins are npm packages that add server and TUI capabilities when numasec
boots. Depending on what the package exports, a plugin can register tools,
themes, prompts, or other runtime extensions through the `@numasec/plugin`
surface.

The source of truth for numasec contributors is this repo and the types
published under `@numasec/plugin`.

### Namespace policy

- `@numasec/*` — *official* plugins, maintained in the numasec monorepo
- `numasec-plugin-*` — community namespace on npm (no pre-approval)
- `@acme/numasec-plugin-*` — private org namespace

### Installing

```sh
numasec plugin <package-name>
numasec plugin <package-name> --global
numasec plugin <package-name> --force
```

Installing a plugin resolves the package, inspects its manifest, and patches the
right numasec config so the plugin is loaded on boot.

### Authoring (pointer)

A plugin is a small TypeScript/JavaScript package exporting a factory that
receives the numasec plugin context and returns tools/themes/prompts. The
authoritative reference is the published `@numasec/plugin` package and the
plugin loader in this repository.

### Pre-flight checks

Plugins that wrap external binaries should declare required binaries in their
own manifest and fail clearly when those binaries are not present on `PATH`.

## Which one do I use?

- Need normal HTTP, browser, scanner, vault, methodology, or CVE primitives?
  Use the built in palette. No plugin required.
- Need something domain specific, such as AD, Kubernetes, mobile, ICS, or web3?
  Write a plugin.
- Need to orchestrate an external binary that does not belong in core? A plugin
  is the right home unless it becomes common denominator functionality.
