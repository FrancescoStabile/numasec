import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const AuthEvaluator: FindingEvaluator = {
  family: "auth",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "auth", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const method = String(value.method ?? "POST")
      const kind = String(value.kind ?? "auth_issue")
      const title =
        String(value.title ?? "") ||
        (
          kind === "default_credentials"
            ? "Default credentials accepted"
            : kind === "common_credentials"
              ? "Common credentials accepted"
              : "Authentication weakness detected"
        )
      out.push({
        family: "auth",
        title,
        description:
          String(value.evidence ?? "") ||
          (
            kind === "default_credentials"
              ? "A default or seeded credential set successfully authenticated against the target login flow."
              : kind === "common_credentials"
                ? "A common or weak credential pair successfully authenticated against the target login flow."
                : "Authentication weakness confirmed with a successful verification step."
          ),
        severity: (value.technical_severity ?? "high") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.9,
        url,
        method,
        parameter: String(value.parameter ?? ""),
        payload: String(value.payload ?? ""),
        root_cause_key: `auth|${url}|${method}|${kind}|${title}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation:
          kind === "default_credentials"
            ? "Disable default or seeded credentials, force unique passwords on first use, and monitor for credential stuffing against bootstrap accounts."
            : kind === "common_credentials"
              ? "Reject common or weak credentials, enforce stronger password policy, and monitor for credential stuffing against exposed login flows."
              : "Harden the authentication flow and remove weak bootstrap or bypass conditions.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
