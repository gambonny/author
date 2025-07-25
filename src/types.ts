import type { GetLoggerFn } from "@gambonny/cflo"
import type { TimingVariables } from "hono/timing"
import type * as v from "valibot"

import type { credentials } from "@/schemas"
import type { WithErrorFn, WithSuccessFn } from "@/lib/httpResponseMaker"

export interface AppEnv extends TimingVariables {
  Bindings: CloudflareBindings
  Variables: {
    traceparent: string
    getLogger: GetLoggerFn
    withSuccess: WithSuccessFn
    withError: WithErrorFn
  }
}

export type ValidationIssues = ReturnType<typeof v.flatten>["nested"]

export type Credentials = v.InferInput<typeof credentials>
