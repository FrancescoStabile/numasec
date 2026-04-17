import { createResource, createSignal, Show } from "solid-js"
import { DialogSelect } from "@tui/ui/dialog-select"
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

export function DialogOperation() {
  const dialog = useDialog()
  const project = useProject()
  const [tick, setTick] = createSignal(true)
  let inflight = false

  const [data] = createResource(tick, async () => {
    if (inflight) return
    inflight = true
    try {
      const dir = project.instance.directory()
      if (!dir) return { ops: [], active: undefined as string | undefined }
      const [ops, activeSlug] = await Promise.all([
        Operation.list(dir).catch(() => []),
        Operation.activeSlug(dir).catch(() => undefined),
      ])
      return { ops, active: activeSlug }
    } finally {
      inflight = false
    }
  })

  return (
    <Show when={data()} fallback={<DialogSelect title="Operations" options={[]} />}>
      {(d) => {
        const options = d().ops.map((op) => ({
          value: op.slug,
          title: `${KIND_GLYPHS[op.kind] ?? "◆"} ${op.label}`,
          description: `${op.kind} · ${op.slug} · ${op.lines} lines${op.target ? ` · ${op.target}` : ""}`,
          category: op.active ? "Active" : "Available",
        }))
        return (
          <DialogSelect
            title="Select operation"
            current={d().active}
            options={options}
            onSelect={async (option) => {
              const dir = project.instance.directory()
              if (!dir) return dialog.clear()
              await Operation.activate(dir, option.value)
              setTick((v) => !v)
              dialog.clear()
            }}
            keybind={[
              {
                title: "deactivate",
                onTrigger: async (option) => {
                  const dir = project.instance.directory()
                  if (!dir) return
                  await Operation.archive(dir, option.value).catch(() => undefined)
                  setTick((v) => !v)
                },
              },
            ]}
          />
        )
      }}
    </Show>
  )
}
