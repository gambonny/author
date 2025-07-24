import * as v from "valibot"

export const urls = v.pipe(
  v.array(v.pipe(v.string(), v.trim(), v.url())),
  v.minLength(1, "At least one valid url is required"),
)
