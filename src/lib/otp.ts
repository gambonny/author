import { Temporal } from "@js-temporal/polyfill"
import { extract } from "@gambonny/valext"

import { otpRecord } from "@/schemas"
import type { OnValidationErrorCallback } from "@/types"

export function generateOtp(): string {
  return Math.floor(Math.random() * 100_000_000)
    .toString()
    .padStart(8, "0")
}

export async function storeOtp(
  env: Cloudflare.Env,
  email: string,
  otp: string,
  onValidationError?: OnValidationErrorCallback,
): Promise<boolean> {
  const { success, output: record } = extract(otpRecord).from(
    { otp, attempts: 0 },
    issues => onValidationError?.(issues),
  )

  if (!success) return false

  await env.STORE.put(otpKey(email), JSON.stringify(record), {
    expiration:
      Temporal.Now.instant().add({ hours: 1 }).epochMilliseconds / 1000,
  })

  return true
}

function otpKey(email: string) {
  return `otp:${email.trim().toLowerCase()}`
}

export async function verifyOtp(
  env: Cloudflare.Env,
  email: string,
  submitted: string,
  onError?: OnValidationErrorCallback,
): Promise<boolean> {
  const key = otpKey(email)
  const { success, output: record } = extract(otpRecord).from(
    await env.STORE.get(key, "json"),
    issues => onError?.(issues),
  )

  if (!success) {
    await env.STORE.delete(key)
    return false
  }

  if (record.otp !== submitted) {
    record.attempts++
    onError?.({ otp: [`otp invalid -- attempt #${record.attempts}`] })
    await env.STORE.put(key, JSON.stringify(record))
    return false
  }

  // silent-delete so we don’t trigger a retry if delete briefly errors
  try {
    await env.STORE.delete(key)
  } catch {
    /* no-op */
  }

  return true
}
