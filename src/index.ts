import { env } from "cloudflare:workers"

import { Hono } from "hono"
import { cors } from "hono/cors"
import { trimTrailingSlash } from "hono/trailing-slash"
import { uaBlocker } from "@hono/ua-blocker"
import { aiBots, useAiRobotsTxt } from "@hono/ua-blocker/ai-bots"
import { extract } from "@gambonny/valext"

import { tao, logger, traceparent, responseMaker } from "@/middlewares"
import { urls } from "@/schemas"
import { routes } from "@/routes"

import type { AppEnv } from "@/types"

const { success, output: origins } = extract(urls).from(
  env.ALLOWED_ORIGINS.split(","),
  issues => console.error(issues),
)

if (!success) throw new Error("Origins invalid")

const app = new Hono<AppEnv>()

app.use(uaBlocker({ blocklist: aiBots }))
app.use("/robots.txt", useAiRobotsTxt())

app.use(cors({ origin: origins, credentials: true }))
app.use(tao({ origin: origins }))

app.use(traceparent())
app.use(trimTrailingSlash())
app.use(logger({ appName: "Author" }))
app.use(responseMaker())

app.route("/", routes)

app.notFound(c => {
  return c.text("Not found", 404)
})

app.onError((err, c) => {
  console.error(`${err}`)
  return c.text("Error", 500)
})

export default app
