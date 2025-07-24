import { useLogger } from "@gambonny/cflo"
import { createMiddleware } from "hono/factory"

export function logger({ appName }: { appName: string }) {
  return createMiddleware(async (c, next) =>
    useLogger({
      level: c.env.LOG_LEVEL,
      format: c.env.LOG_FORMAT,
      context: {
        appName,
        deployId: c.env.CF_VERSION_METADATA.id,
        traceparent: c.get("traceparent"),
      },
    })(c, next),
  )
}
