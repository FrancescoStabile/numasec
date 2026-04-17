# numasec Plugins

numasec has two layers of extensibility.

## 1. Core bundled capabilities (shipped in the binary)

The `recon` tool in core wraps the most common web/OSINT CLI tools under a single
tool slot. No separate install, no npm package, no plugin dance — just install
the target binary (e.g., `nuclei`, `sherlock`) and the agent can drive it.

See [TOOLS.md](./TOOLS.md#recon--osint) for the full list of supported backends.

**Why bundled and not a plugin?** These are table-stakes for anyone doing
security work. Shipping them as external packages would only add friction. The
binaries themselves are not bundled; numasec just orchestrates whatever is on
`PATH`.

## 2. External plugins (community + specialized verticals)

For verticals that are not "common denominator" (cloud, Active Directory,
mobile, ICS, web3, …) numasec exposes the same plugin API as opencode. Plugins
are npm packages that register tools, themes, or prompts when `numasec` boots.

### Namespace policy

- `@numasec/*` — *official* plugins, maintained in the numasec monorepo
- `numasec-plugin-*` — community namespace on npm (no pre-approval)
- `@acme/numasec-plugin-*` — private org namespace; install via `numasec plugin
  install @acme/numasec-plugin-foo`

### Installing

```sh
numasec plugin install <package-name>
numasec plugin list
numasec plugin remove <package-name>
```

Plugins installed this way are resolved at boot time and their tools become
available to every kind (pentest/appsec/osint/security/hacking) unless the
plugin scopes itself.

### Authoring (pointer)

A plugin is a small TypeScript/JavaScript package exporting a factory that
receives the numasec plugin context and returns tools/themes/prompts. The
reference implementation lives in `packages/plugin-ad` (forthcoming); for now
see the opencode plugin docs, which numasec is compatible with, plus the
internal types exposed under `numasec/plugin`.

### Pre-flight checks

Plugins that wrap external binaries should declare required binaries in their
manifest and call `which` before dispatching. The `recon` tool in core is the
reference implementation of this pattern.

## Which one do I use?

- Need `nuclei` / `sherlock` / `ffuf` / etc? Use the built-in `recon` tool. No
  plugin required.
- Building something domain-specific (AD BloodHound pipeline, Kubernetes audit,
  mobile frida instrumentation, etc.)? Write an external plugin.
- Contributing a wrapper for a popular web/OSINT binary? Open a PR against
  `src/tool/recon.ts` — we add it to the core table.
