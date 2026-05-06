import { createMemo, createResource, createSignal, Match, Show, Switch } from "solid-js"
import { DialogSelect } from "@tui/ui/dialog-select"
import { DialogPrompt } from "@tui/ui/dialog-prompt"
import { useDialog } from "@tui/ui/dialog"
import { useProject } from "@tui/context/project"
import { useKeybind } from "@tui/context/keybind"
import { Operation, type OperationKind } from "@/core/operation"
import { DialogOperationRename } from "./dialog-operation-rename"

const KIND_GLYPHS: Record<OperationKind, string> = {
  pentest: "◆",
  appsec: "◈",
  osint: "●",
  hacking: "✕",
  bughunt: "✦",
  ctf: "▲",
  research: "◇",
}

const KINDS: OperationKind[] = ["pentest", "appsec", "osint", "hacking", "bughunt", "ctf", "research"]

// Empty-state → 2-step create wizard (label → kind).
// Populated → select/activate/deactivate existing ops + "+ new" entry.
export function DialogOperation() {
  const dialog = useDialog()
  const project = useProject()
  const keybind = useKeybind()
  // Boolean-flip tick (≤2 distinct source values) — integer ticks make createResource
  // treat every refetch as a new source, stacking in-flight work. See commit 43ff009.
  const [tick, setTick] = createSignal(true)
  const refresh = () => setTick((v) => !v)
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

  // The outer box is load-bearing: opentui's insertExpression has a
  // `while (typeof v === "function") v = v()` loop that unwraps SolidJS memos
  // (Switch/Show both return createMemo — a function). Without the box wrapper the
  // loop subscribes the *parent* render-effect to data() and stage(), causing it to
  // recreate this component on every async fetch completion → infinite RAM growth.
  // A concrete opentui node (box) is not a function, so the loop stops here and all
  // reactivity is handled by the box's own internal render-effects.
  return (
    <box>
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
            const options = createMemo(() => [
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
            ])
            return (
              <DialogSelect
                title={d().ops.length === 0 ? "Operations (empty — create one)" : "Select operation"}
                current={d().active}
                options={options()}
                onSelect={async (option) => {
                  if (option.value === NEW) {
                    setPendingLabel("")
                    setStage("new-label")
                    return
                  }
                  const dir = d().dir
                  if (!dir) return dialog.clear()
                  await Operation.activate(dir, option.value)
                  refresh()
                  dialog.clear()
                }}
                keybind={[
                  {
                    keybind: keybind.all.session_rename?.[0],
                    title: "rename",
                    onTrigger: (option) => {
                      if (option.value === NEW) return
                      const op = d().ops.find((item) => item.slug === option.value)
                      if (!op) return
                      dialog.replace(() => <DialogOperationRename slug={op.slug} label={op.label} onRenamed={refresh} />)
                    },
                  },
                  {
                    title: "deactivate",
                    onTrigger: async (option) => {
                      if (option.value === NEW) return
                      const dir = d().dir
                      if (!dir) return
                      await Operation.archive(dir, option.value).catch(() => undefined)
                      refresh()
                    },
                  },
                ]}
              />
            )
          }}
        </Show>
      </Match>
    </Switch>
    </box>
  )
}

function describeKind(k: OperationKind): string {
  switch (k) {
    case "pentest":
      return "authorized penetration test against a client system → pentest agent"
    case "appsec":
      return "application-security review, DAST/SAST/SCA, remediation → appsec agent"
    case "osint":
      return "open-source intelligence gathering → osint agent"
    case "hacking":
      return "offensive R&D, exploit dev, binary/web hacking → hacking agent"
    case "bughunt":
      return "bug bounty / responsible-disclosure hunt → pentest agent"
    case "ctf":
      return "capture-the-flag or training exercise → hacking agent"
    case "research":
      return "security research, threat modelling, PoC work → security agent"
  }
}
