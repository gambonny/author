import type { Context } from "hono"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { ValidationIssues } from "@/types"

interface SuccessPayload<T> {
  status: "success"
  message: string
  resource_url: string
  data?: T
}

interface ErrorPayload {
  status: "error"
  message: string
  resource_url: string
  issues?: ValidationIssues
}

function isSuccess<T>(
  type: "success" | "error",
  dataOrIssues: T | ValidationIssues,
): dataOrIssues is T {
  return type === "success"
}

function buildPayload<T>(
  c: Context,
  type: "success",
  message: string,
  data?: T,
): SuccessPayload<T>

function buildPayload(
  c: Context,
  type: "error",
  message: string,
  issues?: ValidationIssues,
): ErrorPayload

function buildPayload<T>(
  c: Context,
  type: "success" | "error",
  message: string,
  dataOrIssues?: T | ValidationIssues,
): SuccessPayload<T> | ErrorPayload {
  const { origin, pathname } = new URL(c.req.url)
  const base = { status: type, message, resource_url: origin + pathname }

  if (isSuccess(type, dataOrIssues)) {
    return {
      ...base,
      ...(dataOrIssues && Object.keys(dataOrIssues).length > 0
        ? { data: dataOrIssues }
        : {}),
    }
  }

  return {
    ...base,
    issues: dataOrIssues,
  }
}

export type SuccessFn = <T>(
  msg: string,
  data?: T,
  statusCode?: ContentfulStatusCode,
) => Response

export type ErrorFn = (
  msg: string,
  issues?: ValidationIssues,
  statusCode?: ContentfulStatusCode,
) => Response

export function makeHttpResponse(c: Context): {
  success: SuccessFn
  error: ErrorFn
} {
  const success: SuccessFn = (message, data, status = 200) => {
    const payload = buildPayload(c, "success", message, data)
    return c.json(payload, status)
  }

  const error: ErrorFn = (message, issues, status = 400) => {
    const payload = buildPayload(c, "error", message, issues)
    return c.json(payload, status)
  }

  return { success, error }
}
