import type { GetLoggerFn } from "@gambonny/cflo"
import type { TimingVariables } from "hono/timing"
import type * as v from "valibot"

import type { makeHasher } from "@/lib/hasher"
import type { credentials } from "@/schemas"
import type { ErrorFn, SuccessFn } from "@/lib/httpResponseMaker"
import type { BackoffFn } from "@/middlewares"

export interface AppEnv extends TimingVariables {
  Bindings: CloudflareBindings
  Variables: {
    traceparent: string
    getLogger: GetLoggerFn
    http: { success: SuccessFn; error: ErrorFn }
    hash: ReturnType<typeof makeHasher>
    backoff: BackoffFn
  }
}

export type ValidationIssues = ReturnType<typeof v.flatten>["nested"]
export type OnValidationErrorCallback = (issues: ValidationIssues) => void

export type Credentials = v.InferInput<typeof credentials>
