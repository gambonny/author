# Author

Authentication Worker Template — Manage signup, login, OTP, and password reset flows for SPAs.

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
| POST   | `/signup/verify`  | Verify the OTP sent to the user.                    |
| POST   | `/login`          | Validate credentials, return tokens via cookies.    |
| POST   | `/password/reset` | Start password reset, sends token via email.        |
| POST   | `/password/update`| Set new password after reset token is verified.     |
| POST   | `/me`             | Validate the current session and return user info.  |


## ⚙️ Requirements
This Worker uses several Cloudflare features. You must set up the following:

### Secrets (required)
These must be configured via `npx wrangler secret put` and also added to `.dev.vars` for local development:

```bash
HASH_PEPPER=...
RESEND=...
JWT_SECRET=...
```
> You must have an account with Resend and use a valid API key.

### Resources
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

This will create a `users` table and a supporting index with the following structure:

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
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

```jsonc
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
