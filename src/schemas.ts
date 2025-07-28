import * as v from "valibot"

export const urls = v.pipe(
  v.array(v.pipe(v.string(), v.trim(), v.url())),
  v.minLength(1, "At least one valid url is required"),
)

// Fields
export const email = v.pipe(
  v.string(),
  v.trim(),
  v.nonEmpty("Email is required"),
  v.email(),
)

export const password = v.pipe(
  v.string(),
  v.minLength(8, "Password must be at least 8 characters long"),
)

export const otpCode = v.pipe(v.string(), v.length(8))
const token = v.pipe(v.string(), v.trim(), v.minLength(10))

// Auth
export const credentials = v.strictObject({ email, password })
export const jwtValue = v.object({
  id: v.number(),
  email,
  exp: v.number(),
  iat: v.number(),
})

// Opt
export const otpRecord = v.object({
  otp: otpCode,
  attempts: v.pipe(
    v.number(),
    v.minValue(0),
    v.maxValue(2, "too many attempts"),
  ),
})

export const otpPayload = v.object({
  email: email,
  otp: otpCode,
})

// Remember password
export const rememberEmail = v.object({ email })
export const resetPasswordRecord = v.object({ token, email })
