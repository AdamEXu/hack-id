# SAML 2.0 Integration API

This is the implementation-focused guide for integrating a SAML Service Provider (SP) with hack.sv ID as your Identity Provider (IdP).

If SAML login fails, start with **[Troubleshooting](#troubleshooting)**.

## Quick Start (Working Baseline)

### 1. Configure IdP environment

Set these in `.env`:

```env
BASE_URL=https://id.your-domain.com
SAML_ENABLED=true
SAML_IDP_ENTITY_ID=https://id.your-domain.com/saml/metadata
SAML_IDP_KEY_ACTIVE_PATH=/run/secrets/saml_idp_key_active.pem
SAML_IDP_CERT_ACTIVE_PATH=/run/secrets/saml_idp_cert_active.pem
SAML_XMLSEC_BINARY=/usr/bin/xmlsec1
```

If you are testing from local development, use a public HTTPS tunnel URL for `BASE_URL` (not `http://127.0.0.1:3000`).

### 2. Create an active key/cert pair

Example:

```bash
openssl req -x509 -newkey rsa:2048 -keyout saml_idp_key_active.pem -out saml_idp_cert_active.pem \
  -days 3650 -nodes -subj "/CN=id.your-domain.com"
```

Mount these files into the container path used by your env vars.

### 3. Create a SAML app in admin

Use the admin UI (`/admin/apps`) or API.

If you use the API directly, include both an authenticated admin session and a valid CSRF token:

```bash
curl -sS -X POST https://id.your-domain.com/admin/apps \
  -H 'Content-Type: application/json' \
  -H "X-CSRFToken: YOUR_CSRF_TOKEN" \
  -b admin_session_cookie.txt \
  --data '{
    "name": "Example SAML App",
    "icon": "https://example.com/icon.png",
    "app_type": "saml",
    "allow_anyone": false,
    "saml_metadata_url": "https://sp.example.com/metadata.xml",
    "saml_entity_id": "https://sp.example.com/metadata",
    "saml_acs_url": "https://sp.example.com/saml/acs",
    "saml_enabled": true
  }'
```

Notes:
- `allow_anyone=true` is rejected for SAML apps.
- `saml_entity_id` and `saml_acs_url` are required when `saml_enabled=true`.

### 4. Pull SP metadata from URL and apply

```bash
curl -sS -X POST https://id.your-domain.com/admin/apps/APP_ID/saml/fetch-metadata \
  -H 'Content-Type: application/json' \
  -H "X-CSRFToken: YOUR_CSRF_TOKEN" \
  -b admin_session_cookie.txt \
  --data '{"saml_metadata_url":"https://sp.example.com/metadata.xml"}'
```

If response has `"requires_approval": true`, approve:

```bash
curl -sS -X POST https://id.your-domain.com/admin/apps/APP_ID/saml/approve-metadata \
  -H "X-CSRFToken: YOUR_CSRF_TOKEN" \
  -b admin_session_cookie.txt
```

### 5. Add access policy (ACL)

SAML apps use app ACL checks at runtime. Add the users/groups that should be allowed to sign in to this app.

### 6. Configure your SP to trust hack.sv ID

Use IdP metadata URL:

```text
https://id.your-domain.com/saml/metadata
```

This metadata publishes:
- IdP `entityID`
- SSO endpoints (`/saml/sso`, Redirect + POST bindings)
- SLO endpoints (`/saml/slo`, Redirect + POST bindings)
- IdP signing cert(s)

### 7. Run an SP-initiated login

Start login from your SP. The SP should send `AuthnRequest` to:

- `GET /saml/sso` (Redirect binding) or
- `POST /saml/sso` (POST binding)

On success, the browser is POSTed to your SP ACS URL with `SAMLResponse`.

---

## Runtime Endpoints

### `GET /saml/metadata`

Public IdP metadata endpoint (no auth required).

### `GET|POST /saml/sso`

SP-initiated SSO endpoint.

Required:
- `SAMLRequest`

Optional:
- `RelayState`

Behavior:
- Resolves app by `Issuer` from the SAML message.
- Rejects unknown, inactive, or non-SAML apps.
- Enforces ACL before issuing assertion.
- Enforces signed AuthnRequest policy when app requires it.

### `POST /saml/apps/<app_id>/launch`

IdP-initiated launch endpoint (dashboard-driven).

Important:
- `POST` only.
- CSRF-protected and same-site origin checked.

### `GET|POST /saml/slo`

Single logout endpoint for `LogoutRequest` / `LogoutResponse`.

### `GET /saml/continue`

Continuation endpoint used after login/registration/profile completion for deferred SAML flows.

---

## Metadata Sync Endpoints (Admin)

All require an authenticated admin with apps permissions.

- `POST /admin/apps/<app_id>/saml/fetch-metadata`
- `POST /admin/apps/<app_id>/saml/approve-metadata`
- `POST /admin/apps/<app_id>/saml/reject-metadata`
- `GET /admin/apps/<app_id>/saml/sync-status`
- `GET /admin/apps/<app_id>/saml/audit`

Material metadata changes are staged for approval. Non-material changes are auto-applied.

Material changes include:
- `saml_entity_id`
- `saml_acs_url`
- `saml_acs_binding`
- `saml_slo_url`
- SP signing cert set
- signed-request requirement

---

## Attribute Mapping

`saml_attribute_mapping` is a JSON array. Each entry:

```json
{
  "source_field": "email",
  "saml_name": "email",
  "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
  "required": true,
  "multi_valued": false,
  "transform": "identity"
}
```

Allowed `source_field` values:
- `email`
- `legal_name`
- `preferred_name`
- `pronouns`
- `dob`
- `discord_id`
- `events`
- `display_name`

Allowed `transform` values:
- `identity`
- `lowercase`
- `uppercase`

Validation:
- duplicate `saml_name` values are rejected
- unsupported source fields are rejected
- `required=true` with missing value fails assertion issuance

---

## Testing (Recommended Workflow)

Use this order:

1. Local/staging first with a public HTTPS tunnel and explicit `BASE_URL`.
2. Configure your SP/test tool against that tunnel metadata URL.
3. Verify all flows (SP-initiated, IdP-initiated, SLO).
4. Promote to production only after passing the same checks.

Do not test first in production.

### Tunnel example

```env
BASE_URL=https://abc123.ngrok.app
SAML_IDP_ENTITY_ID=https://abc123.ngrok.app/saml/metadata
```

Then set your SP IdP metadata URL to:

```text
https://abc123.ngrok.app/saml/metadata
```

---

## Troubleshooting

| Symptom | Response | Root Cause | Fix |
|---|---|---|---|
| `Missing SAMLRequest` | `400` | SP did not send SAMLRequest | Send AuthnRequest to `/saml/sso` |
| `No active SAML app configured for Issuer` | `400` | `Issuer` does not match any active SAML app `saml_entity_id` | Align SP entity ID and app config |
| `Signed AuthnRequest required for this app` | `400` | App requires signed requests but request is unsigned | Enable signed AuthnRequests on SP and publish signing cert in metadata |
| `You do not have access to this SAML application.` | `403` | ACL denied user | Add ACL entry/group membership for this app |
| Redirect to registration during SSO | `302` to `/register` | Profile not complete | Complete profile, then `/saml/continue` resumes flow |
| Metadata fetch blocked | `400` from fetch endpoint | URL is not HTTPS, resolves to non-public IP, or bad XML | Use valid public HTTPS metadata URL |
| `Invalid launch origin` | `403` | IdP-initiated launch POST failed same-site/origin checks | Launch from dashboard UI with valid CSRF/session |

---

## Integration Checklist

Before going live:

1. `BASE_URL` is correct for your deployment hostname.
2. IdP key/cert files exist and are readable in container paths.
3. `GET /saml/metadata` is reachable publicly over HTTPS.
4. SAML app is `app_type=saml`, active, and `saml_enabled=true`.
5. App has correct `saml_entity_id` and `saml_acs_url`.
6. ACL entries exist for intended users/groups.
7. Metadata sync has no pending unapproved material changes.
8. SP-initiated SSO and SLO both pass in staging/tunnel.

---

## Security Notes

- SAML metadata URL onboarding enforces HTTPS, public-IP resolution checks, redirect controls, and response size/time limits.
- SAML POST-binding is CSP-limited to the app ACS origin on SAML response pages.
- Keep IdP private keys in secret-managed files and rotate with active/next cert strategy.
- Keep `SAML_ENABLED=false` in environments where key material is not provisioned.
