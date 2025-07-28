import { Hono } from "hono"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"
import { getCookie } from "hono/cookie"

import { extract } from "@gambonny/valext"
import { sign as jwtSign } from "@tsndr/cloudflare-worker-jwt"
import { Temporal } from "@js-temporal/polyfill"

import { credentials, otpPayload } from "@/schemas"
import { hashPassword, salt } from "@/lib/crypto"
import { generateOtp, storeOtp, verifyOtp } from "@/lib/otp"
import { clearAuthCookies, issueAuthCookies } from "@/lib/cookies"
import authMiddleware from "@/middlewares"
import type { AppEnv, Credentials, JwtValue, OtpPayload } from "@/types"

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
        input: { db: { DurableObject: dbResult.meta.duration } },
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

        return http.error("unknown error", {}, 500)
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

      return http.error("unknown error", {}, 500)
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

    if (!success) return c.var.http.error("invalid input")

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

      if (!verified) return http.error("activation failed")
    } catch (e: unknown) {
      logger.error("otp:verification:failed", {
        event: "otp.verification.failed",
        scope: "kv.otp",
        input: { otp },
        error: e instanceof Error ? e.message : String(e),
      })

      return http.error("activation failed")
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

        return http.error("activation failed")
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

      return http.error("Unknown error", {}, 500)
    }
  },
)
routes.post(
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
      `SELECT id, password_hash, salt, active
         FROM users
        WHERE email = ?`,
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

      return http.error("Invalid email or password", {}, 401)
    }

    const computed = await hashPassword(password, row.salt)
    if (computed !== row.password_hash) {
      logger.warn("login:failed", {
        event: "login.invalid-credentials",
        scope: "auth.session",
      })

      return http.error("Invalid email or password", {}, 401)
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

      return http.error("unknown error", 500)
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
