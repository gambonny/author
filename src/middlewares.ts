import { createMiddleware } from "hono/factory"

import { useLogger } from "@gambonny/cflo"
import { backOff, type BackoffOptions } from "exponential-backoff"

import { makeHttpResponse } from "@/lib/httpResponseMaker"
import { makeHasher } from "@/lib/hasher"
import type { AppEnv } from "@/types"

/**
 * Middleware that enforces presence of the `traceparent` header.
 *
 * This acts as a structural contract: every incoming request must be
 * traceable to a client-triggered interaction. By requiring a traceparent ID:
 *
 * - We guarantee that no request enters the system without an identifiable origin.
 * - We enable end-to-end correlation between consumers actions and backend logs.
 * - We reduce attack surface by rejecting unstructured or synthetic traffic.
 *
 * Requests missing this header are rejected with a vague 400 response,
 * preserving system intent without revealing internal requirements.
 *
 * This middleware should run first, before logger setup or route handling.
 */

export function traceparent() {
  return createMiddleware(async (c, next) => {
    const traceparent = c.req.header("traceparent")

    if (!traceparent) {
      console.warn("request.rejected", {
        reason: "missing_traceparent",
        path: c.req.path,
      })

      return c.text("Bad request", 400)
    }

    c.set("traceparent", traceparent)

    await next()
  })
}

/**
 * Middleware to append `Timing-Allow-Origin` headers.
 */

interface TaoOptions {
  origin: string | ReadonlyArray<string>
}

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

export function responseMaker() {
  return createMiddleware((c, next) => {
    c.set("http", makeHttpResponse(c))
    return next()
  })
}

export const hasherMaker = () =>
  createMiddleware<AppEnv>(async (c, next) => {
    const pepper = c.env.HASH_PEPPER

    if (!pepper) {
      console.error("HASH_PEPPER env var missing")
      return c.text("Internal error", 500)
    }

    c.set("hash", makeHasher(pepper))
    await next()
  })

export type BackoffFn = <T>(
  fn: () => Promise<T>,
  opts?: BackoffOptions,
) => Promise<T>

export function backoffMaker(defaultOptions: BackoffOptions) {
  return createMiddleware(async (c, next) => {
    c.set(
      "backoff",
      <T>(fn: () => Promise<T>, opts?: BackoffOptions): Promise<T> => {
        return backOff(fn, { ...defaultOptions, ...opts })
      },
    )

    await next()
  })
}
