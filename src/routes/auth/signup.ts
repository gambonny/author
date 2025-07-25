import { Hono } from "hono"
import { timing } from "hono/timing"
import { validator } from "hono/validator"
import { extract } from "@gambonny/valext"

import { credentials } from "@/lib/auth/schemas"
import type { AppEnv } from "@/types"

export const signupRoute = new Hono<AppEnv>()

signupRoute.post(
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

    if (!success) return c.text("Invalid input")

    return output
  }),
  async (c): Promise<Response> => {
    return c.text("holi")
  },
)
