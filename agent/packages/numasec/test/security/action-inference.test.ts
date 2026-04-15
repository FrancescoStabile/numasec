import { describe, expect, test } from "bun:test"
import { actionTarget, inferActionKind, inferActionResourceUrl } from "../../src/security/action-inference"

describe("action inference", () => {
  test("infers broader state-changing actions", () => {
    expect(inferActionKind("https://app.example.com/api/BasketItems/add", "")).toBe("add")
    expect(inferActionKind("https://app.example.com/api/Profile", "Save profile")).toBe("save")
    expect(inferActionKind("https://app.example.com/api/Reviews", "Send the review")).toBe("send")
    expect(inferActionKind("https://app.example.com/api/Tasks", "Submit request")).toBe("submit")
  })

  test("maps target states for broader actions", () => {
    expect(actionTarget("add")).toBe("added")
    expect(actionTarget("save")).toBe("saved")
    expect(actionTarget("send")).toBe("sent")
    expect(actionTarget("submit")).toBe("submitted")
  })

  test("only infers resource URLs when the action is the terminal path segment", () => {
    expect(inferActionResourceUrl("https://app.example.com/api/BasketItems/11/add", "add")).toBe("https://app.example.com/api/BasketItems/11")
    expect(inferActionResourceUrl("https://app.example.com/api/Profile", "save")).toBe("")
  })
})
