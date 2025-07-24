import type { GetLoggerFn } from "@gambonny/cflo"
import type { TimingVariables } from "hono/timing"

export interface AppEnv extends TimingVariables {
  Bindings: CloudflareBindings
  Variables: {
    traceparent: string
    getLogger: GetLoggerFn
  }
}
