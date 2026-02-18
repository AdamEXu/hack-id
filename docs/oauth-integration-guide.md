# OAuth Integration Quick Start Guide

Use OAuth 2.0 authorization code flow only.

## Status

- Legacy `GET /oauth?redirect=...` is removed and returns `410 Gone`.
- Legacy `POST /api/oauth/user-info` token exchange is removed and returns `410 Gone`.
- This guide includes a short compatibility note for one release window; do not build new integrations on legacy endpoints.

## OAuth 2.0 Flow

1. Redirect users to `GET /oauth/authorize` with:
   - `response_type=code`
   - `client_id`
   - `redirect_uri`
   - `scope` (space-separated)
   - `state`
2. Receive `code` on your redirect URI.
3. Exchange code server-to-server at `POST /oauth/token`.
4. Call `GET /api/oauth/user-info` with `Authorization: Bearer <access_token>`.

## JavaScript Example

```javascript
const params = new URLSearchParams({
  response_type: 'code',
  client_id: process.env.HACKID_CLIENT_ID,
  redirect_uri: 'https://your-app.com/oauth/callback',
  scope: 'profile email',
  state: crypto.randomUUID(),
});

window.location.href = `https://id.hack.sv/oauth/authorize?${params.toString()}`;
```

## Token Exchange Example

```bash
curl -X POST https://id.hack.sv/oauth/token \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri="https://your-app.com/oauth/callback" \
  -d client_id="$HACKID_CLIENT_ID" \
  -d client_secret="$HACKID_CLIENT_SECRET"
```

## User Info Example

```bash
curl https://id.hack.sv/api/oauth/user-info \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Compatibility Note (Temporary)

If you still call legacy endpoints, update immediately. They now return `410 Gone` and will not be re-enabled.
