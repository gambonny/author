import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"
import { extract } from "@gambonny/valext"

import { credentials } from "@/schemas"
import type { AppEnv, Credentials } from "@/types"

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

    if (!success) return c.var.withError("invalid input")

    return output
  }),
  async (c): Promise<Response> => {
    const { email, password } = c.req.valid("json") as Credentials

    return c.var.withSuccess(`${email} - ${password}`)
  },
)
