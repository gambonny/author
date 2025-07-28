import { setCookie } from "hono/cookie"
import type { AppContext } from "@/types"

const baseOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "None" as const,
  path: "/",
}

export function setSecureCookie(
  c: AppContext,
  name: string,
  value: string,
  maxAge: number,
) {
  setCookie(c, name, value, { ...baseOptions, maxAge })
}

/** Issue both auth cookies in one call */
export function issueAuthCookies(
  c: AppContext,
  accessToken: string,
  refreshToken: string,
  {
    accessTtl = 60 * 60, // 1 h
    refreshTtl = 60 * 60 * 24 * 14, // 14 d
  } = {},
) {
  setSecureCookie(c, "token", accessToken, accessTtl)
  setSecureCookie(c, "refresh_token", refreshToken, refreshTtl)
}

/** Clear both auth cookies (logout) */
export function clearAuthCookies(c: AppContext) {
  setSecureCookie(c, "token", "", 0)
  setSecureCookie(c, "refresh_token", "", 0)
}
