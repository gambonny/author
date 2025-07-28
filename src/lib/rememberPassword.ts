import { extract } from "@gambonny/valext"
import { resetPasswordRecord } from "@/schemas"
import type { OnValidationErrorCallback } from "@/types"

const EXPIRATION_SECONDS = 60 * 60 // 1 hour

/**
 * Store a reset‐password token in KV.
 * Let KV errors bubble so the route’s backoff can catch/retry them.
 */
export async function storeToken(
  env: Cloudflare.Env,
  email: string,
  token: string,
  onError?: OnValidationErrorCallback,
): Promise<boolean> {
  const { success, output: record } = extract(resetPasswordRecord).from(
    { token, email },
    issues => {
      onError?.(issues)
    },
  )

  if (!success) return false

  await env.STORE.put(resetTokenKey(token), JSON.stringify(record), {
    expirationTtl: EXPIRATION_SECONDS,
  })

  return true
}

/**
 * Verify a reset‐password token.
 * @returns the email if valid, or false on expiration/invalid (and calls onError)
 */
export async function verifyToken(
  env: Cloudflare.Env,
  submitted: string,
  onError?: OnValidationErrorCallback,
): Promise<string | false> {
  const key = resetTokenKey(submitted)

  const { success, output } = extract(resetPasswordRecord).from(
    await env.STORE.get(key, "json"),
    issues => onError?.(issues),
  )

  if (!success) {
    await env.STORE.delete(key)
    return false
  }

  await env.STORE.delete(key)
  return output.email
}

export function resetTokenKey(token: string) {
  return `reset:${token.trim().toLowerCase()}`
}
