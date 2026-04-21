import { createMemo } from "solid-js"
import { useLocal } from "@tui/context/local"
import { DialogSelect } from "@tui/ui/dialog-select"
import { useDialog } from "@tui/ui/dialog"
import { Kind } from "@/core/kind"

export function DialogAgent() {
  const local = useLocal()
  const dialog = useDialog()

  const options = createMemo(() =>
    local.agent.list().map((item) => {
      const pack = Kind.byId(item.name)
      if (pack) {
        return {
          value: item.name,
          title: `${pack.glyph} ${pack.label}`,
          description: pack.tagline,
          category: pack.id === "security" || pack.id === "hacking" ? "Conversational" : "Structured engagement",
        }
      }
      return {
        value: item.name,
        title: item.name,
        description: item.native ? "native" : item.description,
      }
    }),
  )

  return (
    <DialogSelect
      title="Select kind"
      current={local.agent.current()?.name}
      options={options()}
      onSelect={(option) => {
        local.agent.set(option.value)
        dialog.clear()
      }}
    />
  )
}
