# Adele OAuth2

Adele's OAuth2 package provides a standards-compliant authorization server for Adele applications. It ships as an Adele `ServiceProvider` — a blank import auto-registers it with the framework and wires up the token endpoints automatically. The package implements [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) grant types, [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) bearer token usage, and [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) PKCE.

## What Client Type Should I Use?

The client's ability to secure a client secret determines which grant type to use. Adele's OAuth2 server supports the following grant types and flows:

### Authorization Code (Flow: plain)

For server-side web applications that can securely store a client secret. The authorization server issues an authorization code that the server exchanges for an access token. Use `grant_type: authorization_code` with `flow: plain`.

### Authorization Code with PKCE (Flow: pkce)

For single-page applications, mobile apps, and native clients that cannot securely store a client secret. PKCE (Proof Key for Code Exchange) replaces the client secret with a code verifier/challenge pair, preventing authorization code interception. Use `grant_type: authorization_code` with `flow: pkce`.

### Authorization Code with PKCE Implicit (Flow: pkce_implicit)

For limited browser widgets or embedded contexts that do not require a full user permissions flow. The authorization server issues an authorization code directly in the response body rather than via redirect. Access tokens are short-lived and scopes must be whitelisted in `PkceImplicitAuthorizationScopes` before the server will issue them. Use `grant_type: authorization_code` with `flow: pkce_implicit`.

### Client Credentials

For machine-to-machine authentication where no user is involved. The client authenticates with its credentials and receives an access token scoped to application-level resources. Use `grant_type: client_credentials`.

### Password

For trusted first-party clients where the resource owner explicitly provides credentials to the client. This grant is appropriate only when other grant types are not viable. The client submits the user's username and password directly to the token endpoint. Use `grant_type: password`.

## Installation

Install the package:

```bash
go get github.com/cidekar/adele-oauth2
```

Add a blank import to your application's entry point to auto-register the `ServiceProvider`:

```go
import _ "github.com/cidekar/adele-oauth2"
```

The provider registers `POST /oauth/token` and `POST /oauth/token/refresh` automatically. The authorization endpoints (`GET /oauth/authorize` and `POST /oauth/authorize`) require scaffold handlers that you wire up on the consumer side — see the Authorization Endpoints section below.

If you need to pass runtime configuration before the provider boots, call `SetProviderConfig` before your application starts:

```go
import (
    oauth "github.com/cidekar/adele-oauth2"
    "github.com/cidekar/adele-oauth2/api"
)

oauth.SetProviderConfig(map[string]interface{}{
    "guarded_route_groups": []string{"/api"},
    "scopes": api.Scopes{
        "ping": "Allows access to the ping resource",
        "pong": "Allows access to the pong resource",
    },
})
```

## Configuration

The `Configuration` struct controls token lifetimes, scope definitions, and route protection. Values are loaded from `config/oauth.yml` in your application root; missing fields fall back to defaults.

```go
type Configuration struct {
    // Scopes the authorization server may issue to any token request.
    Scopes map[string]string

    // PkceImplicitAuthorizationScopes is the allowlist of scopes that may be
    // issued to pkce_implicit clients. Requests for scopes outside this set
    // are rejected.
    PkceImplicitAuthorizationScopes map[string]string

    // GuardedRouteGroups lists path prefixes that require a valid bearer token.
    // Example: []string{"/api"}
    GuardedRouteGroups []string

    // UnguardedRoutes lists exact paths within guarded groups that bypass
    // token authentication. Example: []string{"/api/health"}
    UnguardedRoutes []string

    // AuthorizationTokenTTL is how long an authorization code remains valid.
    // Default: 60 * time.Minute
    AuthorizationTokenTTL time.Duration

    // OauthTokenTTL is how long an access token remains valid.
    // Default: 24 * time.Hour
    OauthTokenTTL time.Duration

    // RefreshTokenTokenTTL is how long a refresh token remains valid.
    // Default: 24 * time.Hour
    RefreshTokenTokenTTL time.Duration

    // PkceImplicitTTL is how long a pkce_implicit access token remains valid.
    // Default: 300 * time.Second
    PkceImplicitTTL time.Duration

    // VerifyTemplatePath is the path to the authorization consent template,
    // relative to your application's resources directory.
    VerifyTemplatePath string
}
```

To configure the provider programmatically use `SetProviderConfig` with a `map[string]interface{}` using the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `scopes` | `map[string]string` | Scopes the server may issue |
| `pkce_implicit_authorization_scopes` | `map[string]string` | Allowlisted scopes for pkce_implicit clients |
| `guarded_route_groups` | `[]string` | Protected path prefixes |
| `unguarded_routes` | `[]string` | Exempt exact paths within guarded groups |
| `authorization_token_ttl` | `time.Duration` | Authorization code lifetime |
| `oauth_token_ttl` | `time.Duration` | Access token lifetime |
| `pkce_implicit_ttl` | `time.Duration` | PKCE implicit token lifetime |
| `refresh_token_ttl` | `time.Duration` | Refresh token lifetime |
| `verify_template_path` | `string` | Consent form template path |

## Clients

Clients are registered in the `oauth_clients` database table. You may create clients programmatically using `InsertClient`. The `Service` is accessed through the provider — `New` is called internally by the `ServiceProvider` and is not intended to be called by consumers directly. Obtain a `*api.Service` from the provider via `oauth.Provider().Service()`:

```go
svc := oauth.Provider().Service()

client, err := svc.InsertClient(api.Client{
    Name:        "My Application",
    Secret:      "a-strong-random-secret",
    Type:        "authorization_code",
    Flow:        "pkce",
    RedirectUrl: "https://myapp.com/callback",
})
if err != nil {
    // handle error
}

// client.PlainText contains the secret — it is shown once here and
// never stored. The database stores a bcrypt hash.
fmt.Println("Client secret:", client.PlainText)
```

The `Secret` field is hashed with bcrypt at insert time. The plaintext secret is returned in `Client.PlainText` for display to the operator and is not persisted. Store it securely — it cannot be recovered after this point.

**Client fields:**

| Field | Description |
|-------|-------------|
| `Type` | RFC 6749 grant type: `authorization_code`, `client_credentials`, or `password` |
| `Flow` | Sub-flow for `authorization_code` clients: `plain`, `pkce`, or `pkce_implicit` |
| `RedirectUrl` | Required for `authorization_code` clients; must exactly match the `redirect_uri` in authorization requests |

## Scopes

Scopes provide fine-grained access control. Define the scopes your server may issue in the `Configuration.Scopes` map, then annotate routes with the scopes required to access them.

### Defining scopes

```go
oauth.SetProviderConfig(map[string]interface{}{
    "guarded_route_groups": []string{"/api"},
    "scopes": api.Scopes{
        "ping": "Allows access to the ping resource",
        "pong": "Allows access to the pong resource",
    },
})
```

### Annotating routes

Add a scope annotation to any route path. The format is `[scopes:scope1 scope2]`. Multiple scopes are separated by a single space:

```go
r.Post("/api/ping[scopes:ping pong]", func(w http.ResponseWriter, r *http.Request) {
    a.App.WriteJSON(w, http.StatusOK, []string{"pong"})
})
```

A request to `/api/ping` must present a bearer token that has both `ping` and `pong` assigned. Requests missing any required scope receive a `403` response.

### Checking scopes manually

Automatic scope checking covers the majority of cases. When business logic requires checking scopes inside a handler, use `HasScope` or `AnyScope`:

```go
r.Post("/api/ping", func(w http.ResponseWriter, r *http.Request) {
    svc := oauth.New(adeleApp)
    scopes := oauth.Scopes{
        "ping": "Allows access to the ping resource",
        "pong": "Allows access to the pong resource",
    }

    if !svc.HasScope(r, scopes) {
        // handle access denied
        return
    }

    a.App.WriteJSON(w, http.StatusOK, []string{"pong"})
})
```

- `HasScope(r, scopes)` — the bearer token must have **all** listed scopes.
- `AnyScope(r, scopes)` — the bearer token must have **at least one** listed scope.

Both methods extract the token from the request context and compare it against the provided scope map.

## Token Endpoints

The provider auto-registers these endpoints. No manual route definition is required.

### POST /oauth/token

Exchanges credentials for an access token. Supports `client_credentials`, `password`, and `authorization_code` (PKCE code exchange) grant types.

**Client credentials grant:**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=1&client_secret=secret&scopes=ping+pong
```

**Password grant:**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=1&client_secret=secret&username=user@example.com&password=pass&scopes=ping
```

**Authorization code PKCE exchange:**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=1&code=AUTH_CODE&code_verifier=VERIFIER&code_challenge_method=S256&scopes=ping
```

**Successful response (RFC 6749 §5.1):**

```json
{
    "token_type": "Bearer",
    "access_token": "MFRA3NQYJMGC2MJQGEZDGMJXGI3Q",
    "refresh_token": "NBRWKZLTMVRWC3THNFXGO3DFMQ",
    "expires_in": 86400,
    "scope": "ping pong"
}
```

`refresh_token` is omitted for `pkce_implicit` and `client_credentials` flows.

**Client authentication:** `client_id` and `client_secret` may be passed as form body fields or as an HTTP Basic Auth header (`Authorization: Basic base64(client_id:client_secret)`) per RFC 6749 §2.3.1.

**Error response (RFC 6749 §5.2):**

```json
{
    "error": "invalid_client",
    "error_description": "Client authentication failed."
}
```

### POST /oauth/token/refresh

Exchanges a valid refresh token for a new access and refresh token pair. The requested scopes must be a subset of the original token's scopes per RFC 6749.

```
POST /oauth/token/refresh
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&client_id=1&client_secret=secret&refresh_token=REFRESH_TOKEN&scopes=ping
```

**Successful response:**

```json
{
    "token_type": "Bearer",
    "access_token": "NEW_ACCESS_TOKEN",
    "refresh_token": "NEW_REFRESH_TOKEN",
    "expires_in": 86400,
    "scope": "ping"
}
```

The old access token and refresh token are invalidated and deleted on a successful exchange.

### Test Endpoint

The provider registers `GET /api/ping` as a test endpoint for bearer middleware validation. It returns `{"status": "pong"}` and is protected by the bearer token middleware when `/api` is in `GuardedRouteGroups`.

## Authorization Endpoints

`GET /oauth/authorize` and `POST /oauth/authorize` are consumer-side endpoints that your application scaffolds. They render and process the authorization consent form shown to the resource owner.

Wire up the handlers in your routes file:

```go
r.Get("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
    res, errRes := svc.AuthorizationGrantExchange(w, r)
    if errRes != nil {
        // handle error
        return
    }
    // res.CSRFToken must be embedded in the consent form
    // res.RedirectUri.URI contains the full request URL for form action
})

r.Post("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
    res, errRes := svc.AuthorizationGrantExchangePost(w, r)
    if errRes != nil {
        // handle error
        return
    }
    if res.GrantType != "verify" {
        http.Redirect(w, r, res.RedirectUri.URI, http.StatusFound)
    }
})
```

`AuthorizationGrantExchange` (GET) validates the incoming authorization request and generates a CSRF token stored in the session. The consent form template receives the client name, requested scopes, and the original request URL.

`AuthorizationGrantExchangePost` (POST) validates the CSRF token, authenticates the user if not already logged in, and — if the user grants access — issues an authorization code and redirects to the client's `redirect_uri`. The CSRF token is single-use and cleared from the session after validation.

**Required form fields for POST:**

| Field | Description |
|-------|-------------|
| `client_id` | The client identifier |
| `csrf_token` | The CSRF token generated by the GET handler |
| `grant_type` | Must be `authorization_code` |
| `response_type` | Must be `code` |
| `redirect_uri` | Must match the client's registered redirect URL |
| `state` | Opaque value for CSRF protection in the redirect |
| `code_challenge` | PKCE code challenge |
| `code_challenge_method` | `S256` or `plain` |
| `scopes` | Space-delimited list of requested scopes |

The consent form template is configured via `Configuration.VerifyTemplatePath`.

## Middleware

The package provides two middleware functions for protecting routes. Add them to your global middleware stack:

```go
app.Use(svc.AuthenticationTokenMiddleware())
app.Use(svc.AuthenticationCheckForScopes())
```

**`AuthenticationTokenMiddleware`** — validates the bearer token on every request to a path within `GuardedRouteGroups`. It extracts the `Authorization` header, strips the `Bearer` prefix (case-insensitive per RFC 6750), and looks up the token by its SHA-256 hash. Valid tokens are placed into the request context under the `accessToken` key for downstream middleware. Invalid or missing tokens receive a `401` response.

Paths in `UnguardedRoutes` and paths outside `GuardedRouteGroups` pass through without token validation.

**`AuthenticationCheckForScopes`** — runs after `AuthenticationTokenMiddleware`. It reads the scope annotation from the matched route and confirms the token in the request context carries all required scopes. Requests missing any required scope receive a `403` response.

The middleware does not require an `Accept: application/json` header.

## Security

- **Client secrets** — stored as bcrypt hashes using `bcrypt.DefaultCost`. Plaintext is never persisted.
- **Token storage** — access tokens and refresh tokens are stored as SHA-256 hashes. The plaintext token is returned to the caller once at issuance.
- **Constant-time comparisons** — client secret validation uses `bcrypt.CompareHashAndPassword` with a dummy hash on all code paths to prevent timing-based client enumeration.
- **Atomic code consumption** — authorization codes are consumed in a single database operation (`ConsumeAuthorizationToken`). A code cannot be exchanged more than once.
- **CSRF protection** — the authorization consent form is protected by a session-bound, single-use CSRF token generated with `crypto/rand`.
- **Bearer token extraction** — the `Authorization` header prefix match is case-insensitive, following RFC 6750.
