import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const ErrorDisclosureEvaluator: FindingEvaluator = {
  family: "error_disclosure",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "error_disclosure", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      out.push({
        family: "error_disclosure",
        title: String(value.title ?? "Verbose error details exposed to clients"),
        description:
          String(value.evidence ?? "") ||
          "The server returned stack traces or verbose internal error details to the client.",
        severity: (value.technical_severity ?? "low") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.8,
        url,
        method: String(value.method ?? "GET"),
        parameter: "",
        payload: "",
        root_cause_key: `error_disclosure|${url}|${String(value.kind ?? "stacktrace")}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Return generic production error responses to clients and keep stack traces in internal logs only.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
