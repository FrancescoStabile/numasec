import { createResource, createSignal, Show, Match, Switch } from "solid-js"
import { DialogSelect } from "@tui/ui/dialog-select"
import { DialogPrompt } from "@tui/ui/dialog-prompt"
import { useDialog } from "@tui/ui/dialog"
import { useProject } from "@tui/context/project"
import { Operation, type OperationKind } from "@/core/operation"

const KIND_GLYPHS: Record<OperationKind, string> = {
  pentest: "◆",
  ctf: "▲",
  bughunt: "✦",
  osint: "●",
  research: "◇",
}

const KINDS: OperationKind[] = ["pentest", "ctf", "bughunt", "osint", "research"]

// Empty-state → 2-step create wizard (label → kind).
// Populated → select/activate/deactivate existing ops + "+ new" entry.
export function DialogOperation() {
  const dialog = useDialog()
  const project = useProject()
  const [tick, setTick] = createSignal(0)
  const [stage, setStage] = createSignal<"list" | "new-label" | "new-kind">("list")
  const [pendingLabel, setPendingLabel] = createSignal("")
  let inflight = false

  const [data] = createResource(tick, async () => {
    if (inflight) return
    inflight = true
    try {
      const dir = project.instance.directory()
      if (!dir) return { ops: [], active: undefined as string | undefined, dir: undefined as string | undefined }
      const [ops, activeSlug] = await Promise.all([
        Operation.list(dir).catch(() => []),
        Operation.activeSlug(dir).catch(() => undefined),
      ])
      return { ops, active: activeSlug, dir }
    } finally {
      inflight = false
    }
  })

  return (
    <Switch>
      <Match when={stage() === "new-label"}>
        <DialogPrompt
          title="New operation — label"
          placeholder="e.g. Juice Shop audit"
          onConfirm={(value) => {
            const label = value.trim()
            if (!label) return dialog.clear()
            setPendingLabel(label)
            setStage("new-kind")
          }}
          onCancel={() => setStage("list")}
        />
      </Match>
      <Match when={stage() === "new-kind"}>
        <DialogSelect
          title={`Kind for "${pendingLabel()}"`}
          options={KINDS.map((k) => ({
            value: k,
            title: `${KIND_GLYPHS[k]} ${k}`,
            description: describeKind(k),
          }))}
          onSelect={async (option) => {
            const dir = data()?.dir
            if (!dir) return dialog.clear()
            await Operation.create({
              workspace: dir,
              label: pendingLabel(),
              kind: option.value as OperationKind,
            }).catch(() => undefined)
            dialog.clear()
          }}
        />
      </Match>
      <Match when={stage() === "list"}>
        <Show when={data()} fallback={<DialogSelect title="Operations" options={[]} />}>
          {(d) => {
            const NEW = "__new__"
            const options = [
              ...d().ops.map((op) => ({
                value: op.slug,
                title: `${KIND_GLYPHS[op.kind] ?? "◆"} ${op.label}`,
                description: `${op.kind} · ${op.slug} · ${op.lines} lines${op.target ? ` · ${op.target}` : ""}`,
                category: op.active ? "Active" : "Available",
              })),
              {
                value: NEW,
                title: "+ New operation",
                description: "Create a fresh engagement (label → kind)",
                category: "New",
              },
            ]
            return (
              <DialogSelect
                title={d().ops.length === 0 ? "Operations (empty — create one)" : "Select operation"}
                current={d().active}
                options={options}
                onSelect={async (option) => {
                  if (option.value === NEW) {
                    setPendingLabel("")
                    setStage("new-label")
                    return
                  }
                  const dir = d().dir
                  if (!dir) return dialog.clear()
                  await Operation.activate(dir, option.value)
                  setTick((v) => v + 1)
                  dialog.clear()
                }}
                keybind={[
                  {
                    title: "deactivate",
                    onTrigger: async (option) => {
                      if (option.value === NEW) return
                      const dir = d().dir
                      if (!dir) return
                      await Operation.archive(dir, option.value).catch(() => undefined)
                      setTick((v) => v + 1)
                    },
                  },
                ]}
              />
            )
          }}
        </Show>
      </Match>
    </Switch>
  )
}

function describeKind(k: OperationKind): string {
  switch (k) {
    case "pentest":
      return "authorized penetration test against a client system"
    case "ctf":
      return "capture-the-flag challenge or training exercise"
    case "bughunt":
      return "bug bounty / responsible-disclosure hunt"
    case "osint":
      return "open-source intelligence gathering"
    case "research":
      return "security research, reverse engineering, PoC work"
  }
}
