# js

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run index.ts
```

This project was created using `bun init` in bun v1.2.12. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.

## Run the benchmark

Reproducible benchmark against a disposable OWASP Juice Shop clone. No
external test framework — scoring is a rubric over the artifacts numasec
itself produces (`<workspace>/.numasec/operation/<slug>/`).

```bash
# from packages/numasec
bun run bench:local -- --scenario pwn
# also available: --scenario web-surface | --scenario appsec-triage
```

The runner will:

1. Clone juice-shop into a throwaway tmp dir (reuses `localhost:3000` if already up).
2. Boot a headless `numasec serve` on a random port in a throwaway workspace.
3. Send the scenario's slash command (`/pwn`, `/play web-surface`, `/play appsec-triage`) via the public session API.
4. Score the artifacts and write `bench-results-<ts>.json`.
5. Tear everything down.

Safety: the harness will **never** touch a `./juice-shop/` checkout in your
repo root. Every run is a disposable clone.
