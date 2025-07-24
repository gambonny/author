import { createMiddleware } from "hono/factory"

interface TaoOptions {
  origin: string | ReadonlyArray<string>
}

/**
 * Middleware to append `Timing-Allow-Origin` headers.
 */
export function tao({ origin }: TaoOptions) {
  const origins = Array.isArray(origin) ? origin : [origin]

  return createMiddleware(async (c, next) => {
    for (const o of origins) {
      if (!o) continue
      c.header("Timing-Allow-Origin", o, { append: true })
    }

    await next()
  })
}
