# Author

Authentication Worker Template — Manage signup, login, OTP, and password reset flows for SPAs using Hono.

## 🔐 Authentication
This Worker uses `JWT`s to manage user sessions. Tokens are issued on successful login and stored as `HttpOnly` cookies (`token`, `refresh_token`).

The `JWT` payload has the following structure:

```json
{
  "email": "user@example.com",
  "id": 42,
  "exp": 1725630000,
  "iat": 1725626400
}
```

All timestamps are UNIX seconds (exp = expiration, iat = issued at)


## 🔗 Token Verification via `Tokenator`
This Worker does not verify `JWT`s directly — instead, it delegates token validation to a companion Worker called [Tokenator](https://github.com/gambonny/tokenator).

You must:

Deploy `Tokenator`.

Bind it as a service to this Worker in your `wrangler.jsonc`:

```jsonc
{
  "services": [
    {
      "service": "tokenator",
      "binding": "TOKENATOR",
      "entrypoint": "Tokenator"
    }
  ]
}
```

If the token is missing or invalid, protected routes like `/me` will return 401 Unauthorized.


## 🧩 Routes
This Worker exposes the following HTTP endpoints:

| Method | Path              | Description                                          |
|--------|-------------------|------------------------------------------------------|
| POST   | `/signup`         | Register a user. Triggers OTP via workflow.         |
| POST   | `/otp/verify`  | Verify the OTP sent to the user.                    |
| POST   | `/login`          | Validate credentials, return tokens via cookies.    |
| POST   | `/password/remember` | Start password reset, sends token via email.        |
| POST   | `/password/reset`| Set new password after reset token is verified.     |
| GET    | `/me`             | Validate the current session and return user info.  |


# ⚙️ Requirements
This Worker uses several Cloudflare features. You must set up the following:

## Secrets (required)
These must be configured via `npx wrangler secret put` and also added to `.dev.vars` for local development:

```bash
HASH_PEPPER=...
RESEND=...
JWT_SECRET=...
```
> You must have an account with Resend and use a valid API key.

## Resources
This worker depends on the following Cloudflare services. You must create and bind them in `wrangler.jsonc`:


### D1 Database
Used to persist user accounts and activation state.
Create the database:

```bash
npx wrangler d1 create your-db-name
```

Bind it in `wrangler.jsonc`:

```jsonc
{
  "d1_databases": {
    "DB": { "binding": "DB", "database_name": "your-db-name" }
  }
}
```
Run the initial migration:

```bash
npx wrangler d1 migrations apply your-db-name
```

### KV Namespace
Used for OTPs and password-reset tokens.

```bash
npx wrangler kv:namespace create "STORE"
```

Bind it in `wrangler.jsonc`:
```jsonc
{
  "kv_namespaces": [
    { "binding": "STORE", "id": "..." }
  ]
}
```

### Workflows
Required for signup expiration/cleanup logic.

```jsonc
{
  "workflows": {
    "bindings": [
      { "name": "SIGNUP_WFW", "workflow_name": "signup" }
    ]
  }
}
```

# 🧱 Middlewares
This Worker uses layered middlewares to enforce structure, observability, and security. Each middleware contributes to system clarity and traceability.

## 🧬 traceparent
Enforces presence of the traceparent header on every request. <br />

✅ Ensures:

- All incoming traffic is traceable to a user/client action.
- Logs can be correlated end-to-end (frontend ⇄ backend).
- Synthetic or malformed traffic is rejected early.

> If missing, the request is rejected with a vague 400 Bad Request.


## 🧾 logger 
Initializes structured logging with `cflo`. <br />

✅ Benefits:

- Adds deployment info and traceparent ID to each log.
- Ensures all logs follow a consistent schema (appName, route, event, etc).
- Makes it easier to adjust log levels globally.

## 🛠 responseMaker
Adds `http.success()` and `http.error()` to the context. <br />

✅ Benefits:

- Consistent response shape across the app.
- Standardized keys: status, message, resource_url, data, issues.
- Reduces repeated boilerplate when building HTTP responses.

## 🧂 hasherMaker
Injects a `SHA‑256` hasher that includes a pepper. <br />

✅ Why:

- Allows you to hash sensitive data like emails before logging, helping you comply with the principle of data minimization (aligned with laws like GDPR and security best practices).
- Prevents accidental exposure of plaintext credentials in logs.
- Ensures all hashing uses a consistent, non-reversible format with a peppered strategy.
- Keeps the logic centralized — no need to reimplement hashing in every route.

> If HASH_PEPPER is missing, the request is rejected with a 500 Internal Error.


## 🔁 backoffMaker
Adds `c.var.backoff()` utility for exponential retry logic. <br />

✅ Use cases:

- Retrying KV or DB operations that may fail transiently.
- Helps avoid exposing internal failures to users.
- Makes resilience a first-class citizen.

## 🔒 authMiddleware
Protects routes that require a valid `JWT`. <br />

✅ Features:

- Reads `JWT` from the token cookie.
- Verifies it using the `Tokenator` service.
- Logs all failures with detailed event tagging.

If the token is:

- Missing → returns 401 Unauthorized

- Invalid → returns 401 Unauthorized


### 🪵 Logging
This worker uses [cflo](https://github.com/gambonny/cflo) for structured logging. Configure logging with:

```jsonc
{
  "vars": {
    "LOG_LEVEL": "debug", // or "info", "warn", "error"
    "LOG_FORMAT": "json"  // or "pretty"
  }
}
```


## ✅ Quick Start

```bash
pnpm install
pnpm dev
```

## 🧰 Managing Workers with Wireworks
If you're building or scaling multiple Cloudflare Workers, consider using [Wireworks](https://github.com/gambonny/wireworks) — a CLI tool designed to make managing multiple Worker repositories easier, without needing a monorepo or Git submodules.


