# Author

Authentication Worker Template — Manage signup, login, OTP, and password reset flows for SPAs.


## 🧩 Routes
This Worker exposes the following HTTP endpoints:

| Method | Path              | Description                                          |
|--------|-------------------|------------------------------------------------------|
| POST   | `/signup`         | Register a user. Triggers OTP via workflow.         |
| POST   | `/signup/verify`  | Verify the OTP sent to the user.                    |
| POST   | `/login`          | Validate credentials, return tokens via cookies.    |
| POST   | `/password/reset` | Start password reset, sends token via email.        |
| POST   | `/password/update`| Set new password after reset token is verified.     |
| POST   | `/me`             | Validate the current session and return user info.  |


## ⚙️ Requirements
This Worker uses several Cloudflare features. You must set up the following:

1. Secrets (required)
These must be configured via `npx wrangler secret put` and also added to `.dev.vars` for local development:

```bash
HASH_PEPPER=...
RESEND=...
JWT_SECRET=...
```
> You must have an account with Resend and use a valid API key.

2. Resources
This worker depends on the following Cloudflare services. You must create and bind them in `wrangler.jsonc`:


**D1 Database** <br />
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

**KV Namespace** <br />
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

**Workflows** <br />
Required for signup expiration/cleanup logic.

```jsconc
{
  "workflows": {
    "bindings": [
      { "name": "SIGNUP_WFW", "workflow_name": "signup" }
    ]
  }
}
```

## 🪵 Logging
This worker uses `cflo` for structured logging. Configure logging with:

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
