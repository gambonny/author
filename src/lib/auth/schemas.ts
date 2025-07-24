import * as v from "valibot"

export const emailField = v.pipe(
  v.string(),
  v.trim(),
  v.nonEmpty("Email is required"),
  v.email(),
)

export const passwordField = v.pipe(
  v.string(),
  v.minLength(8, "Password must be at least 8 characters long"),
)

export const signupPayload = v.object({
  email: emailField,
  password: passwordField,
})
