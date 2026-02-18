# OAuth 2.0 Integration API

This is the implementation-focused guide for hack.sv ID OAuth 2.0.

If your token exchange is failing, start with **[Token Exchange Troubleshooting](#token-exchange-troubleshooting)**.

## Quick Start (Working Baseline)

### 1. Redirect user to authorize

```text
GET https://id.hack.sv/oauth/authorize?
  response_type=code&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https%3A%2F%2Fyourapp.com%2Foauth%2Fcallback&
  scope=profile%20email&
  state=RANDOM_CSRF_VALUE
```

### 2. Receive code on your callback

```text
https://yourapp.com/oauth/callback?code=AUTH_CODE&state=RANDOM_CSRF_VALUE
```

### 3. Exchange code for token (server-to-server)

```bash
curl -sS -X POST https://id.hack.sv/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=AUTH_CODE' \
  --data-urlencode 'redirect_uri=https://yourapp.com/oauth/callback' \
  --data-urlencode 'client_id=YOUR_CLIENT_ID' \
  --data-urlencode 'client_secret=YOUR_CLIENT_SECRET'
```

### 4. Call user info with Bearer token

```bash
curl -sS https://id.hack.sv/api/oauth/user-info \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

---

## Exact Endpoint Requirements

### `GET /oauth/authorize`

Required query params:
- `response_type=code`
- `client_id`
- `redirect_uri`

Recommended:
- `scope` (space-separated, e.g. `profile email`)
- `state`

Validation behavior:
- `client_id` must reference an active app.
- `redirect_uri` must exactly match one configured URI for that app.
- Requested scopes must be a subset of app allowed scopes.
- User must be allowed by app access policy (ACL/open access).

If invalid, the user sees an error page and no auth code is issued.

### `POST /oauth/token`

Required body fields:
- `grant_type=authorization_code`
- `code`
- `redirect_uri`
- `client_id`
- `client_secret`

Important:
- Request body must be form-encoded (`application/x-www-form-urlencoded`).
- JSON body is not accepted by this endpoint.
- Send `client_id` and `client_secret` in the form body.
- `redirect_uri` must match the URI used when code was issued, exactly.

Success response (`200`):

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "profile email"
}
```

Error response (`400`):

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid, expired, or already used authorization code"
}
```

### `GET /api/oauth/user-info`

Headers:
- `Authorization: Bearer ACCESS_TOKEN`

Success (`200`) returns scoped fields. `is_admin` is always included.

Common failures:
- `401 invalid_request`: missing/invalid Authorization header
- `401 invalid_token`: token invalid, expired, or revoked

### `POST /oauth/revoke`

Form body:
- `token`

Always returns `200 {"success": true}` per OAuth revocation behavior.

---

## Token Exchange Troubleshooting

If `/oauth/token` fails, compare exactly against this table:

| Symptom | Response | Root Cause | Fix |
|---|---|---|---|
| Missing/empty form fields | `400 invalid_request` | One or more required params missing | Send all five required fields |
| Wrong grant type | `400 unsupported_grant_type` | Not using `authorization_code` | Use `grant_type=authorization_code` |
| Bad client credentials | `400 invalid_client` | Wrong `client_id` or `client_secret` | Verify app credentials from `/admin/apps` |
| Code rejected | `400 invalid_grant` | Code expired (10 min), already used, wrong `client_id`, or redirect mismatch | Get a fresh code and re-check exact redirect URI |
| Works in Postman, fails in app | Often `invalid_request` or `invalid_grant` | App sends JSON or mutates `redirect_uri` | Send form-encoded body and preserve URI exactly |
| OAuth library sends `Authorization: Basic ...` only | `400 invalid_request` | Endpoint expects `client_id` and `client_secret` in form body | Configure library to include client credentials in POST body |

### The most common mismatch

`redirect_uri` must be **byte-for-byte identical** between:
1. the `/oauth/authorize` request,
2. the callback URL where code is received,
3. the `/oauth/token` exchange.

Common mismatches:
- trailing slash differences (`/callback` vs `/callback/`)
- different scheme (`http` vs `https`)
- different host (`localhost` vs `127.0.0.1`)
- different port
- accidental URL-decoding/re-encoding changes

---

## Integration Checklist

Before blaming tokens, verify:

1. App is active in `/admin/apps`.
2. Your callback URL is listed in app redirect URIs exactly.
3. Your user is allowed to access the app (open access or ACL entry/group).
4. You are requesting only scopes enabled on the app.
5. You verify `state` in callback before exchanging code.
6. You exchange the code only once and within 10 minutes.
7. Your token request is form-encoded, not JSON.

---

## Minimal Backend Example (Node/Express)

```javascript
import express from 'express';
import crypto from 'node:crypto';

const app = express();
app.use(express.json());

const CLIENT_ID = process.env.HACKID_CLIENT_ID;
const CLIENT_SECRET = process.env.HACKID_CLIENT_SECRET;
const REDIRECT_URI = 'https://yourapp.com/oauth/callback';

app.get('/login', (req, res) => {
  const state = crypto.randomUUID();
  req.session.oauth_state = state;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'profile email',
    state,
  });

  res.redirect(`https://id.hack.sv/oauth/authorize?${params.toString()}`);
});

app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) return res.status(400).send('Missing code');
  if (state !== req.session.oauth_state) return res.status(400).send('Invalid state');

  const tokenRes = await fetch('https://id.hack.sv/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });

  const tokenJson = await tokenRes.json();
  if (!tokenRes.ok) return res.status(400).json({ step: 'token', tokenJson });

  const meRes = await fetch('https://id.hack.sv/api/oauth/user-info', {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });

  const meJson = await meRes.json();
  if (!meRes.ok) return res.status(400).json({ step: 'user-info', meJson });

  req.session.user = meJson;
  res.redirect('/dashboard');
});
```

---

## Legacy Endpoint Status

Legacy flow is removed:
- `GET /oauth` returns `410 Gone`
- `POST /api/oauth/user-info` (legacy token-in-body flow) returns `410 Gone`

Use only:
1. `GET /oauth/authorize`
2. `POST /oauth/token`
3. `GET /api/oauth/user-info`

---

## Available Scopes

| Scope | Description | Data Included |
|---|---|---|
| `profile` | Basic profile information | `legal_name`, `preferred_name`, `pronouns` |
| `email` | Email address | `email` |
| `dob` | Date of birth | `dob` |
| `events` | Event enrollment | `events` |
| `discord` | Discord account | `discord_id`, `discord_username` |

---

## Security Notes

- Keep `client_secret` server-side only.
- Always validate `state`.
- Use HTTPS in production.
- Request minimal scopes.
