<p align="center"><img src="https://github.com/user-attachments/assets/2347ad25-9a6e-4d5f-b55b-81ee062874a2" width="400" alt="Adele Logo"></p>

# Adele OAuth2

A first-party OAuth2 authorization server package for the Adele Go framework. Implements RFC 6749 (OAuth 2.0 Authorization Framework), RFC 6750 (Bearer Token Usage), and RFC 7636 (PKCE) compliant flows. Ships as an Adele ServiceProvider with automatic route registration, bearer token middleware, and scope-based access control. Supports authorization code (with and without PKCE), client credentials, and password grants.

## Supported Grant Types

| Grant Type | Client Type | Flow | Use Case |
|---|---|---|---|
| `authorization_code` | `plain` | Server-side apps with secure secret storage | Web apps |
| `authorization_code` | `pkce` | Public clients (SPAs, mobile, native apps) | Browser/mobile |
| `authorization_code` | `pkce_implicit` | Public clients, no user consent, short-lived tokens | Limited-scope browser widgets |
| `client_credentials` | — | Machine-to-machine, no user context | Service accounts |
| `password` | — | Trusted first-party apps with direct credential access | Legacy/internal tools |

## Quick Start

```bash
go get github.com/cidekar/adele-oauth2
```

Blank-import the package to auto-register the ServiceProvider:

```go
import (
    _ "github.com/cidekar/adele-oauth2"
)
```

The ServiceProvider automatically registers:

- `GET /oauth/authorize` — authorization request (renders consent)
- `POST /oauth/authorize` — authorization grant exchange
- `POST /oauth/token` — token exchange
- `POST /oauth/token/refresh` — refresh token exchange
- `GET /api/ping` — test endpoint for bearer middleware validation

Optional provider configuration:

```go
app.Provider.SetProviderConfig("oauth", map[string]interface{}{
    "guarded_route_groups": []string{"/api"},
    "scopes": map[string]string{
        "read":  "Read access",
        "write": "Write access",
    },
})
```

## Documentation

For complete documentation including installation, configuration, scopes, middleware, and client management, see the [full documentation](./docs/oauth.md).

## License

Copyright 2025 Cidekar, LLC. All rights reserved.

[Apache License 2.0](./LICENSE)
