import { createResource, createSignal, Show } from "solid-js"
import { DialogSelect } from "@tui/ui/dialog-select"
import { useDialog } from "@tui/ui/dialog"
import { useProject } from "@tui/context/project"
import { Kind } from "@/core/kind"
import { Operation, OperationActive } from "@/core/operation"

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
      const [ops, active] = await Promise.all([
        Operation.list(dir).catch(() => []),
        OperationActive.getActiveSlug(dir).catch(() => undefined),
      ])
      return { ops, active }
    } finally {
      inflight = false
    }
  })

  return (
    <Show when={data()} fallback={<DialogSelect title="Operations" options={[]} />}>
      {(d) => {
        const options = d().ops.map((op) => {
          const pack = Kind.byId(op.kind)
          return {
            value: op.slug,
            title: `${pack?.glyph ?? "◆"} ${op.label}`,
            description: `${op.kind} · ${op.slug} · ${op.sessions.length} runs · ${op.status}`,
            category: op.status === "active" ? "Active" : "Archived",
          }
        })
        return (
          <DialogSelect
            title="Select operation"
            current={d().active}
            options={options}
            onSelect={async (option) => {
              const dir = project.instance.directory()
              if (!dir) return dialog.clear()
              await OperationActive.setActive(dir, option.value)
              setTick((v) => !v)
              dialog.clear()
            }}
            keybind={[
              {
                title: "archive",
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
