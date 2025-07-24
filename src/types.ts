import type { GetLoggerFn } from "@gambonny/cflo"

export interface AppEnv {
  Bindings: CloudflareBindings
  Variables: {
    traceparent: string
    getLogger: GetLoggerFn
  }
}
