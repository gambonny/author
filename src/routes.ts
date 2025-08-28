import { Hono } from "hono"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"
import { getCookie } from "hono/cookie"

import { extract } from "@gambonny/valext"
import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"
import { Temporal } from "@js-temporal/polyfill"
import { Resend } from "resend"

import {
  credentials,
  otpPayload,
  rememberEmail,
  resetPasswordPayload,
} from "@/schemas"
import { hashPassword, salt, sha256hex } from "@/lib/crypto"
import { generateOtp, storeOtp, verifyOtp } from "@/lib/otp"
import { clearAuthCookies, issueAuthCookies } from "@/lib/cookies"
import { resetTokenKey, storeToken, verifyToken } from "@/lib/rememberPassword"
import authMiddleware from "@/middlewares"
import type {
  AppEnv,
  Credentials,
  JwtValue,
  OtpPayload,
  RememberEmail,
  ResetPasswordPayload,
} from "@/types"

export const routes = new Hono<AppEnv>()

routes.post(
  "/signup",
  timing({ totalDescription: "signup-request" }),
  validator("json", async (body, c) => {
    const { success, output } = extract(credentials).from(body, issues =>
      c.var
        .getLogger({ route: "author.signup.validator" })
        .warn("signup:validation:failed", {
          event: "validation.failed",
          scope: "validator.schema",
          input: body,
          issues,
        }),
    )

    if (!success) return c.var.http.error("invalid input")

    return output
  }),
  async (c): Promise<Response> => {
    const { http } = c.var
    const { email, password } = c.req.valid("json") as Credentials

    const logger = c.var.getLogger({
      route: "author.signup.handler",
      hashed_email: c.var.hash(email),
    })

    logger.debug("signup:started", {
      event: "handler.started",
      scope: "handler.init",
    })

    try {
      logger.debug("generating:credentials", {
        event: "crypto.init",
        scope: "crypto.password",
      })

      const generatedSalt = salt()
      const passwordHash = await hashPassword(password, generatedSalt)
      const otp = generateOtp()

      logger.debug("user:registration:init", {
        event: "db.insert.start",
        scope: "db.users",
      })

      const dbResult = await c.env.DB.prepare(
        "INSERT INTO users (email, password_hash, salt) VALUES (?,?,?)",
      )
        .bind(email, passwordHash, generatedSalt)
        .run()

      setMetric(c, "db.duration", dbResult.meta.duration)
      logger.info("user:registration:success", {
        event: "db.insert.success",
        scope: "db.users",
        input: { db: { duration: dbResult.meta.duration } },
      })

      try {
        const stored = await c.var.backoff(
          () =>
            storeOtp(c.env, email, otp, issues => {
              logger.error("otp:schema:invalid", {
                event: "otp.schema.failed",
                scope: "otp.schema",
                issues,
              })
            }),
          {
            retry: (e, attempt) => {
              logger.debug("otp:store:attempt", {
                input: otp,
                attempt,
                event: "otp.store.attempt",
                scope: "kv.otp.backoff.retry",
                error: e instanceof Error ? e.message : String(e),
              })

              return true
            },
          },
        )

        if (!stored) return http.error("error during otp creation")
      } catch (e: unknown) {
        logger.error("otp:storage:failed", {
          event: "otp.store.failed",
          scope: "kv.otp",
          input: { otp },
          error: e instanceof Error ? e.message : String(e),
        })

        return http.error("unknown error", { general: ["Unknown error"] }, 500)
      }

      const workflow = await c.env.SIGNUP_WFW.create({
        params: { email, otp },
      })

      logger.info("workflow:created", {
        event: "workflow.created",
        scope: "workflow.signup",
        workflow: workflow.id,
      })

      return http.success("User registered, email with otp has been sent", 201)
    } catch (e: unknown) {
      if (e instanceof Error) {
        if (e.message.includes("UNIQUE constraint failed")) {
          logger.warn("user:registration:failed:email:taken", {
            event: "db.insert.conflict",
            scope: "db.users",
            reason: "email taken",
          })

          return http.error(
            "Invalid input",
            { email: ["User already exists"] },
            409,
          )
        }
      }

      logger.error("user:registration:error", {
        event: "signup.error",
        scope: "db.users",
        error: e instanceof Error ? e.message : String(e),
      })

      return http.error(
        "unknown error",
        {
          general: ["Unknown error"],
        },
        500,
      )
    }
  },
)

routes.post(
  "/otp/verify",
  timing({ totalDescription: "otp-verify-request" }),
  validator("json", async (body, c) => {
    const { success, output } = extract(otpPayload).from(body, issues => {
      c.var
        .getLogger({ route: "author.otp.validator" })
        .warn("otp:validation:failed", {
          event: "validation.failed",
          scope: "validator.schema",
          input: body,
          issues,
        })
    })

    if (!success) {
      return c.var.http.error("activation failed", {
        general: ["Activation failed"],
      })
    }

    return output
  }),
  async (c): Promise<Response> => {
    const { http } = c.var
    const { email, otp } = c.req.valid("json") as OtpPayload

    const logger = c.var.getLogger({
      route: "otp.verify.handler",
      hashed_email: c.var.hash(email),
    })

    logger.debug("otp:started", {
      event: "handler.started",
      scope: "handler.init",
    })

    try {
      const verified = await c.var.backoff(
        () =>
          verifyOtp(c.env, email, otp, issues => {
            logger.warn("otp:record:malformed", {
              event: "otp.retrieval.failed",
              scope: "otp.schema",
              input: { otp },
              issues,
            })
          }),
        {
          retry: (e, attempt) => {
            logger.debug("otp:verification:attempt", {
              input: otp,
              attempt,
              event: "otp.verification.attempt",
              scope: "kv.otp.backoff.retry",
              error: e instanceof Error ? e.message : String(e),
            })

            return true
          },
        },
      )

      if (!verified) {
        return http.error("activation failed", {
          general: ["Activation failed"],
        })
      }
    } catch (e: unknown) {
      logger.error("otp:verification:failed", {
        event: "otp.verification.failed",
        scope: "kv.otp",
        input: { otp },
        error: e instanceof Error ? e.message : String(e),
      })

      return http.error("activation failed", {
        general: ["Activation failed"],
      })
    }

    try {
      const user = await c.env.DB.prepare(
        "SELECT id FROM users WHERE email = ?  AND active = false",
      )
        .bind(email)
        .first<{ id: number }>()

      if (!user) {
        logger.warn("user:get:failed", {
          event: "user.not.found",
          scope: "db.users",
        })

        return http.error("activation failed", {
          general: ["Activation failed"],
        })
      }

      const result = await c.env.DB.prepare(
        "UPDATE users SET active = true WHERE email = ?",
      )
        .bind(email)
        .run()

      if (result.meta.changes === 1) {
        logger.info("user:activated", {
          event: "user.validated",
          scope: "db.users",
          input: { db: { duration: result.meta.duration } },
        })

        setMetric(c, "db.duration", result.meta.duration)

        const accessPayload = {
          id: user.id,
          email,
          exp: Math.floor(Date.now() / 1000) + 60 * 60,
          iat: Temporal.Now.instant().epochMilliseconds,
        } satisfies JwtValue

        const refreshPayload = {
          id: user.id,
          email,
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14,
          iat: Temporal.Now.instant().epochMilliseconds,
        } satisfies JwtValue

        const accessToken = await jwtSign(accessPayload, c.env.JWT_SECRET)
        const refreshToken = await jwtSign(refreshPayload, c.env.JWT_SECRET)
        issueAuthCookies(c, accessToken, refreshToken)

        return http.success("user activated")
      }

      logger.warn("user:activated:failed", {
        event: "user.activation.failed",
        scope: "db.users",
        input: { otp },
      })

      return http.error("activation failed")
    } catch (err) {
      logger.error("db:error", {
        event: "db.error",
        scope: "db.users",
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error("Unknown error", { general: ["Unknown error"] }, 500)
    }
  },
)

routes.get(
  "/me",
  timing({ totalDescription: "me-request" }),
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "author.me.handler" })
    const token = getCookie(c, "token")
    const { http } = c.var

    if (!token) {
      logger.log("token:not:present")
      return http.error("issues with token", {}, 401)
    }

    try {
      const user = await c.var.backoff<JwtValue | false>(
        () => c.env.TOKENATOR.decodeToken(token),
        {
          retry: (err, attempt) => {
            const isNetworkError = err instanceof TypeError
            const isServerError = err?.status >= 500

            if (isNetworkError || isServerError) {
              logger.warn("sentinel.validateToken retry", {
                attempt,
                error: err.message,
              })
              return true
            }

            return false
          },
        },
      )

      if (!user) {
        logger.error("invalid:token", { token })
        return http.error("token invalid", {}, 401)
      }

      return http.success("token active", user)
    } catch (e: unknown) {
      logger.error("error:validating:token", {
        error: e instanceof Error ? e.message : String(e),
      })

      return http.error("an unknown error occurred", {}, 500)
    }
  },
)

routes.post(
  "/login",
  timing({ totalDescription: "login-request" }),
  validator("json", async (body, c) => {
    const { success, output } = extract(credentials).from(body, issues => {
      c.var
        .getLogger({ route: "author.login.validator" })
        .warn("login:validation:failed", {
          event: "validation.failed",
          scope: "validator.schema",
          input: output,
          issues,
        })
    })

    if (!success) return c.var.responder.error("Invalid input")

    return output
  }),
  async (c): Promise<Response> => {
    const { http } = c.var
    const { email, password } = c.req.valid("json") as Credentials

    const logger = c.var.getLogger({
      route: "author.login.handler",
      hashed_email: c.var.hash(email),
    })

    logger.debug("login:started", {
      event: "login.attempt",
      scope: "auth.session",
    })

    const row = await c.env.DB.prepare(
      `SELECT id, password_hash, salt, active FROM users WHERE email = ?`,
    )
      .bind(email)
      .first<{
        id: number
        password_hash: string
        salt: string
        active: number
      }>()

    if (!row || row.active !== 1) {
      logger.warn("email:not:found", {
        event: "email.not.found",
        scope: "db.users",
        reason: "user doesn't exist in the database",
      })

      return http.error(
        "Invalid email or password",
        { general: ["invalid user or password"] },
        401,
      )
    }

    const computed = await hashPassword(password, row.salt)
    if (computed !== row.password_hash) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
      })

      return http.error(
        "Invalid email or password",
        { general: ["invalid user or password"] },
        401,
      )
    }

    const now = Math.floor(Date.now() / 1000)
    const accessPayload = {
      id: row.id,
      email,
      exp: now + 60 * 60,
      iat: now,
    } satisfies JwtValue

    const refreshPayload = {
      id: row.id,
      email,
      exp: now + 60 * 60,
      iat: now,
    } satisfies JwtValue

    try {
      const accessToken = await jwtSign(accessPayload, c.env.JWT_SECRET)
      const refreshToken = await jwtSign(refreshPayload, c.env.JWT_SECRET)
      issueAuthCookies(c, accessToken, refreshToken)

      logger.info("login:success", {
        event: "login.success",
        scope: "auth.session",
        input: { userId: row.id },
      })

      return http.success("Logged in successfully")
    } catch (e: unknown) {
      logger.error("error:issuing:token", {
        error: e instanceof Error ? e.message : String(e),
      })

      return http.error("unknown error", { general: ["Unknown error"] }, 500)
    }
  },
)

routes.post(
  "/logout",
  timing({ totalDescription: "logout-request" }),
  authMiddleware,
  async c => {
    const logger = c.var.getLogger({ route: "auth.logout.handler" })

    logger.debug("user:logout", {
      event: "logout.started",
      scope: "auth.session",
    })

    clearAuthCookies(c)

    logger.log("user:logout:success", {
      event: "logout.success",
      scope: "auth.session",
    })

    return c.var.http.success("Logged out")
  },
)

routes.post(
  "/password/remember",
  timing({ totalDescription: "password-remember-request" }),
  validator("json", async (body, c) => {
    const { success, output } = extract(rememberEmail).from(body, issues => {
      c.var
        .getLogger({ route: "author.forgot.validator" })
        .warn("password:forgot:validation:failed", {
          event: "validation.failed",
          scope: "validator.schema",
          input: body,
          issues,
        })
    })

    if (!success) return c.var.responder.error("Invalid input")

    return output
  }),
  async (c): Promise<Response> => {
    const { http } = c.var
    const { email } = c.req.valid("json") as RememberEmail

    const logger = c.var.getLogger({
      route: "author.remember.password.handler",
      hashed_email: c.var.hash(email),
    })

    logger.info("remember:password:started", {
      event: "handler.started",
      scope: "auth.password",
    })

    const user = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?  AND active = true",
    )
      .bind(email)
      .first<{ id: number }>()

    if (!user) {
      logger.info("email:not:found", {
        event: "user.not.found",
        scope: "db.users",
        hashed_email: c.var.hash(email),
      })

      // Return 200 to avoid disclosing existence
      return http.success("email sent")
    }

    const rawToken = crypto.randomUUID()
    const tokenHash = await sha256hex(rawToken)

    try {
      const stored = await c.var.backoff(
        () =>
          storeToken(c.env, email, tokenHash, issues => {
            logger.error("password:forgot:token-store-schema-failed", {
              event: "kv.password.schema.failed",
              scope: "kv.password",
              issues,
            })
          }),
        {
          retry: (err, attempt) => {
            logger.debug("token-store-retry", {
              attempt,
              error: err instanceof Error ? err.message : String(err),
            })

            return true
          },
        },
      )

      if (!stored) {
        return http.error(
          "Failed to generate reset token, please try again later",
          {
            general: ["Failed to generate reset token, please try again later"],
          },
          500,
        )
      }
    } catch (e: unknown) {
      logger.error("token-store-failed", {
        event: "kv.password.store.failed",
        scope: "kv.password",
        error: e instanceof Error ? e.message : String(e),
      })

      return http.error(
        "Failed to generate reset token, please try again later",
        { general: ["Failed to generate reset token, please try again later"] },
        500,
      )
    }

    logger.info("password:forgot:token-generated", {
      event: "token.generated",
      scope: "kv.password",
    })

    try {
      const resend = new Resend(c.env.RESEND)
      const { error } = await c.var.backoff(
        () =>
          resend.emails.send({
            from: "me@mail.example.com",
            to: email,
            subject: "Your password reset token",
            html: `<p>Your reset token is <strong>${rawToken}</strong>. It expires in 1 hour.</p>`,
          }),
        {
          retry: (err, attempt) => {
            const msg = err instanceof Error ? err.message : String(err)
            const isTransient =
              msg.includes("429") ||
              msg.includes("timeout") ||
              /^5\d\d/.test(msg)

            if (isTransient) {
              logger.debug("email-retry", {
                attempt,
                error: msg,
              })
            }

            return isTransient
          },
        },
      )

      if (error) throw new Error(error.message)

      return http.success(
        "If that email is registered, you’ll receive reset instructions shortly",
        201,
      )
    } catch (err: unknown) {
      logger.error("email-send-failed", {
        event: "email.send.failed",
        scope: "auth.password",
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error(
        "Failed to send reset email, please try again later",
        { general: ["Failed to generate reset token, please try again later"] },
        500,
      )
    }
  },
)

routes.post(
  "/password/reset",
  timing({ totalDescription: "password-reset-request" }),
  validator("json", async (body, c) => {
    const { success, output } = extract(resetPasswordPayload).from(
      body,
      issues => {
        c.var
          .getLogger({ route: "author.reset.validator" })
          .warn("password:reset:validation:failed", {
            event: "validation.failed",
            scope: "validator.schema",
            input: body,
            issues,
          })
      },
    )

    if (!success) return c.var.responder.error("Invalid input")

    return output
  }),
  async (c): Promise<Response> => {
    const { token, password } = c.req.valid("json") as ResetPasswordPayload
    const { http } = c.var
    const logger = c.var.getLogger({ route: "author.reset.handler" })

    const hashedToken = await sha256hex(token)

    let email: string | false
    try {
      email = await c.var.backoff(
        () =>
          verifyToken(c.env, hashedToken, issues => {
            logger.warn("token:malformed", {
              event: "reset-token.malformed",
              scope: "kv.reset-token.schema",
              issues,
            })
          }),
        {
          retry: (err, attempt) => {
            logger.debug("token-verify-retry", {
              attempt,
              error: err instanceof Error ? err.message : String(err),
            })

            return true
          },
        },
      )

      if (!email) {
        return http.error(
          "Token has expired, please request a new one",
          { general: ["Token has expired, please request a new one"] },
          410,
        )
      }
    } catch (err: unknown) {
      logger.error("token-verify-failed", {
        event: "kv.password.verify.failed",
        scope: "kv.password",
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error("Token verification failed, please try again", {}, 500)
    }

    const user = await c.env.DB.prepare(
      "SELECT id, salt FROM users WHERE email = ?",
    )
      .bind(email)
      .first<{ id: number; salt: string }>()

    if (!user) {
      logger.warn("user-notfound", {
        event: "email.notfound",
        scope: "db.users",
      })

      return http.error(
        "Token has expired, please request a new one",
        { general: ["Token has expired, please request a new one"] },
        404,
      )
    }

    const passwordHash = await hashPassword(password, user.salt)
    const result = await c.env.DB.prepare(
      "UPDATE users SET password_hash = ? WHERE id = ?",
    )
      .bind(passwordHash, user.id)
      .run()

    setMetric(c, "db.duration", result.meta.duration)
    logger.info("success", {
      event: "password.reset.success",
      scope: "db.users",
      input: { db: { duration: result.meta.duration } },
    })

    try {
      await c.env.STORE.delete(resetTokenKey(token))
    } catch {}

    return http.success("Password has been successfully reset")
  },
)

routes.post(
  "/refresh",
  timing({ totalDescription: "refresh-request" }),
  async (c): Promise<Response> => {
    const logger = c.var.getLogger({ route: "author.refresh.handler" })
    const { http, backoff } = c.var

    const refreshToken = getCookie(c, "refresh_token")
    if (!refreshToken) {
      logger.info("refresh:no-refresh-token")
      return http.error("No refresh token", {}, 401)
    }

    try {
      const user = await backoff<JwtValue | false>(
        () => c.env.TOKENATOR.decodeToken(refreshToken),
        {
          retry: (err, attempt) => {
            const isNetwork = err instanceof TypeError
            const isServer = err?.status >= 500
            if (isNetwork || isServer) {
              logger.warn("refresh:token-validate-retry", {
                attempt,
                error: err.message,
              })

              return true
            }

            return false
          },
        },
      )

      if (!user) {
        logger.warn("refresh:invalid-refresh-token")
        return http.error("Invalid refresh token", {}, 401)
      }

      const now = Math.floor(Date.now() / 1000)
      const accessPayload = {
        id: user.id,
        email: user.email,
        exp: now + 60 * 60,
        iat: now,
      } satisfies JwtValue

      const refreshPayload = {
        id: user.id,
        email: user.email,
        exp: now + 60 * 60 * 24 * 14,
        iat: now,
      } satisfies JwtValue

      const newAccessToken = await jwtSign(accessPayload, c.env.JWT_SECRET)
      const newRefreshToken = await jwtSign(refreshPayload, c.env.JWT_SECRET)
      issueAuthCookies(c, newAccessToken, newRefreshToken)

      logger.info("refresh:success")
      return http.success("Token refreshed")
    } catch (err: unknown) {
      logger.error("refresh:error", {
        error: err instanceof Error ? err.message : String(err),
      })

      return http.error("Could not refresh token, please try again", {}, 500)
    }
  },
)
