import { describe, expect, test } from "bun:test"
import { SessionProcessor } from "../../src/session/processor"

describe("session processor tool evidence surfacing", () => {
  test("applies ingested canonical node ids to json tool output and metadata", () => {
    const merged = SessionProcessor.applyIngestedToolEvidence({
      output: JSON.stringify({
        status: 200,
        ok: true,
      }),
      metadata: {
        actorSessionID: "actor-1",
      },
      ingested: {
        artifacts: 1,
        observations: 0,
        verifications: 1,
        external: 0,
        artifactNodeIDs: ["ENOD-ARTIFACT"],
        observationNodeIDs: [],
        verificationNodeIDs: ["ENOD-VERIFY"],
        nodeIDsByKey: {
          exchange: "ENOD-ARTIFACT",
          "verification:0": "ENOD-VERIFY",
        },
      },
    })

    expect((merged.metadata as any).artifactNodeID).toBe("ENOD-ARTIFACT")
    expect((merged.metadata as any).verificationNodeID).toBe("ENOD-VERIFY")
    expect((merged.metadata as any).nodeIDsByKey.exchange).toBe("ENOD-ARTIFACT")

    const parsed = JSON.parse(merged.output) as Record<string, unknown>
    expect(parsed.canonical_node_ids).toEqual({
      artifact_node_id: "ENOD-ARTIFACT",
      artifact_node_ids: ["ENOD-ARTIFACT"],
      verification_node_id: "ENOD-VERIFY",
      verification_node_ids: ["ENOD-VERIFY"],
      node_ids_by_key: {
        exchange: "ENOD-ARTIFACT",
        "verification:0": "ENOD-VERIFY",
      },
    })
  })

  test("appends canonical node ids to non-json tool output", () => {
    const merged = SessionProcessor.applyIngestedToolEvidence({
      output: "plain text output",
      ingested: {
        artifacts: 0,
        observations: 1,
        verifications: 0,
        external: 0,
        artifactNodeIDs: [],
        observationNodeIDs: ["ENOD-OBS"],
        verificationNodeIDs: [],
        nodeIDsByKey: {
          candidate: "ENOD-OBS",
        },
      },
    })

    expect(merged.output).toContain("Canonical node ids:")
    expect(merged.output).toContain("ENOD-OBS")
  })
})
