# hack.sv ID API Documentation

Welcome to the hack.sv ID API documentation. This API provides secure access to user authentication and management services for hack.sv events and applications.

## Base URL

-   **Production**: `https://id.hack.sv`
-   **Development**: `http://127.0.0.1:3000`

## Authentication

All API endpoints require authentication using API keys with Bearer token authentication:

```http
Authorization: Bearer hack.sv.{YOUR_API_KEY}
```

### Getting an API Key

1. Log in to the admin panel at `/admin`
2. Navigate to "API Key Management"
3. Create a new API key with appropriate permissions
4. Copy the generated key (shown only once)

## Available APIs

### OAuth Integration

-   **Endpoints**: `/oauth/authorize`, `/oauth/token`, `/api/oauth/user-info` (GET)
-   **Purpose**: OAuth 2.0 authorization code flow for external app authentication and user data retrieval
-   **Documentation**: [OAuth API](./oauth.md)
-   **Required Permission**: None for OAuth 2.0 user info (Bearer access token from `/oauth/token`)

### Event Registration

-   **Endpoint**: `/api/register-event`
-   **Purpose**: Register users for events and optionally submit temporary event information (address, emergency contacts, etc.)
-   **Required Permission**: `events.register`

### User Status

-   **Endpoint**: `/api/user-status`
-   **Purpose**: Get user's event registration and temporary info status
-   **Required Permission**: `users.read`

### Event Information

-   **Endpoints**: `/api/events`, `/api/current-event`
-   **Purpose**: Read event details and configurations
-   **Required Permission**: `events.read`

## Permissions

API keys can be configured with the following permissions:

### Events

-   `events.register` - Register users for events
-   `events.submit_info` - Submit temporary event information
-   `events.read` - Read event details and configurations

### Users

-   `users.read` - Read user information and status
-   `users.write` - Modify user data
-   `users.delete` - Delete user accounts and data

### Admin

-   `admin.read` - Read admin-level information and statistics
-   `admin.write` - Perform admin-level operations

### Discord

-   `discord.manage` - Manage Discord roles and user verification

### Analytics

-   `analytics.read` - Read analytics and usage statistics

## Rate Limits

API requests are rate-limited based on your API key configuration:

-   **Development**: 60 requests per minute (default)
-   **Testing**: 120 requests per minute
-   **Production Light**: 300 requests per minute
-   **Production Heavy**: 600 requests per minute
-   **High Volume**: 1200 requests per minute
-   **Unlimited**: Admin only

Rate limit headers are included in responses:

-   `X-RateLimit-Limit`: Requests allowed per minute
-   `X-RateLimit-Remaining`: Requests remaining in current window
-   `X-RateLimit-Reset`: Time when rate limit resets

## Error Handling

### HTTP Status Codes

-   `200 OK` - Request successful
-   `400 Bad Request` - Invalid request parameters
-   `401 Unauthorized` - Missing or invalid API key
-   `403 Forbidden` - Insufficient permissions
-   `404 Not Found` - Resource not found
-   `429 Too Many Requests` - Rate limit exceeded
-   `500 Internal Server Error` - Server error

### Error Response Format

```json
{
    "success": false,
    "error": "Error description"
}
```

## Security

### HTTPS

-   All production API calls must use HTTPS
-   HTTP is only supported in development environments

### API Key Security

-   Store API keys securely (environment variables, secure vaults)
-   Never expose API keys in client-side code
-   Rotate API keys regularly
-   Use minimum required permissions

### Data Privacy

-   User data is handled according to our [Privacy Policy](https://hack.sv/privacy)
-   Sensitive data (addresses, emergency contacts) has limited retention
-   Users can delete their data at any time

## Support

### Documentation

-   API Documentation: This repository
-   Privacy Policy: https://hack.sv/privacy
-   Terms of Service: https://hack.sv/terms

### Contact

-   Technical Support: team@hack.sv
-   Security Issues: security@hack.sv
-   General Inquiries: hello@hack.sv

### Status

-   System Status: https://status.hack.sv
-   Incident Reports: https://status.hack.sv/incidents

## Changelog

### v1.1.0 (2025-07-28)

-   Added OAuth integration API
-   Added temporary token system with 120-second expiration
-   Enhanced API key permission system
-   Improved error handling and documentation

### v1.0.0 (2025-07-01)

-   Initial API release
-   Event registration endpoints
-   User management endpoints
-   API key authentication system
