import { createSignal } from "solid-js"
import { Operation } from "@/core/operation"
import { useProject } from "@tui/context/project"
import { DialogPrompt } from "@tui/ui/dialog-prompt"
import { useDialog } from "@tui/ui/dialog"

export function DialogOperationRename(props: { slug: string; label?: string; onRenamed?: () => void }) {
  const dialog = useDialog()
  const project = useProject()
  const [busy, setBusy] = createSignal(false)

  return (
    <DialogPrompt
      title="Rename Operation"
      value={props.label}
      busy={busy()}
      busyText="Renaming operation..."
      onConfirm={async (value) => {
        const label = value.trim()
        const dir = project.instance.directory()
        if (!label || !dir || busy()) return
        setBusy(true)
        await Operation.rename(dir, props.slug, label).catch(() => undefined)
        props.onRenamed?.()
        dialog.clear()
      }}
      onCancel={() => dialog.clear()}
    />
  )
}
