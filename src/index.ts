import { env } from "cloudflare:workers"

import { Hono } from "hono"
import { cors } from "hono/cors"
import { trimTrailingSlash } from "hono/trailing-slash"
import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"

import { extractOrigins } from "@/schemas"
import { tao } from "@/middlewares/tao"
import { traceparent } from "@/middlewares/traceparent"
import { logger } from "@/middlewares/logger"
import type { AppEnv } from "@/types"

const {
  success,
  output: origin,
  issues,
} = extractOrigins(env.ALLOWED_ORIGINS.split(","))

if (!success) {
  console.warn("config.origin.invalid", { issues })
  throw new Error("Invalid Origins")
}

const app = new Hono<AppEnv>()

app.use(uaBlocker({ blocklist: aiBots }))
app.use("/robots.txt", useAiRobotsTxt())

app.use(cors({ origin, credentials: true }))
app.use(tao({ origin }))

app.use(traceparent())
app.use(trimTrailingSlash())
app.use(logger({ appName: "Author" }))

app.get("/message", c => {
  return c.text("Hello Hono!")
})

app.notFound(c => {
  return c.text("Not found", 404)
})

app.onError((err, c) => {
  console.error(`${err}`)
  return c.text("Error", 500)
})

export default app
