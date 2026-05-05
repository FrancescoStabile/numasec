import { createSimpleContext } from "./helper"

export type SessionView = "chat" | "findings" | "evidence" | "replay" | "workflow" | "report"

export const SESSION_VIEWS: SessionView[] = ["chat", "findings", "evidence", "replay", "workflow", "report"]

export const { use: useSessionView, provider: SessionViewProvider } = createSimpleContext({
  name: "SessionView",
  init: (props: {
    view: () => SessionView
    setView: (view: SessionView) => void
  }) => ({
    get current() {
      return props.view()
    },
    set(view: SessionView) {
      props.setView(view)
    },
  }),
})
