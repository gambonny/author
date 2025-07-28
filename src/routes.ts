import { Hono } from "hono"
import { timing, setMetric } from "hono/timing"
import { validator } from "hono/validator"
import { extract } from "@gambonny/valext"

import { credentials } from "@/schemas"
import type { AppEnv, Credentials } from "@/types"
import { hashPassword, salt } from "@/lib/crypto"
import { generateOtp, storeOtp } from "@/lib/otp"

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
