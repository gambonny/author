import * as v from "valibot"
import { extract } from "@/lib/valibot"

const originsSchema = v.pipe(
  v.array(v.pipe(v.string(), v.trim(), v.url())),
  v.minLength(1, "At least one valid origin is required"),
)

export function extractOrigins(origins: unknown) {
  return extract(originsSchema, origins)
}
