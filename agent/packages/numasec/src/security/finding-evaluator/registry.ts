import type { FindingEvaluator } from "./base"
import { AuthEvaluator } from "./auth"
import { ErrorDisclosureEvaluator } from "./error-disclosure"
import { SqlInjectionEvaluator } from "./sql-injection"
import { IdorEvaluator } from "./idor"
import { MassAssignmentEvaluator } from "./mass-assignment"
import { JwtEvaluator } from "./jwt"
import { CorsEvaluator } from "./cors"
import { MetricsEvaluator } from "./metrics"

export const FindingEvaluators: FindingEvaluator[] = [
  AuthEvaluator,
  SqlInjectionEvaluator,
  IdorEvaluator,
  MassAssignmentEvaluator,
  JwtEvaluator,
  CorsEvaluator,
  MetricsEvaluator,
  ErrorDisclosureEvaluator,
]
