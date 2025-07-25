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

// Auth
export const credentials = v.strictObject({ email, password })
