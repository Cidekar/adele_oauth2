package api

import (
	"log"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/cidekar/adele-framework/database"
	"github.com/cidekar/adele-framework/mux"
	"github.com/cidekar/adele-framework/render"
)

// Scopes represents a map of scope names to their descriptions.
//
// Example:
//
//	scopes := Scopes{
//		"read":  "Read access to resources",
//		"write": "Write access to resources",
//	}
type Scopes = map[string]string

// Configuration holds the OAuth2 server configuration loaded from oauth.yml.
//
// Example (oauth.yml):
//
//	Scopes:
//	  read: "Read access"
//	  write: "Write access"
//	UnguardedRoutes:
//	  - /oauth/token
//	  - /health
//	OauthTokenTTL: 24
//	RefreshTokenTokenTTL: 168
type Configuration struct {
	PkceImplicitAuthorizationScopes map[string]string `yaml:"PkceImplicitAuthorizationScopes"` // scopes that the authorization server may assign to a pkce implicit authorization code request
	Scopes                          Scopes            `yaml:"Scopes"`                          // scopes that the authorization server may assign to a oauth token request
	UnguardedRoutes                 []string          `yaml:"UnguardedRoutes"`                 // paths that do not require authentication (relative paths may not omit leading slash)
	GuardedRouteGroups              []string          `yaml:"GuardedRouteGroups"`              // paths that require authentication (relative paths may omit leading slash)
	AuthorizationTokenTTL           time.Duration     `yaml:"AuthorizationTokenTTL"`           // number of minutes the authorization token is valid
	OauthTokenTTL                   time.Duration     `yaml:"OauthTokenTTL"`                   // number of hours a oauth token is valid
	PkceImplicitTTL                 time.Duration     `yaml:"PkceImplicitTTL"`                 // number of minutes a pkce implicit token is valid
	RefreshTokenTokenTTL            time.Duration     `yaml:"RefreshTokenTokenTTL"`            // number of hours a refresh token is valid
	VerifyTemplatePath              string            `yaml:"VerifyTemplatePath"`              // the path to the verify view template relative to the resources dir
}

// Service provides the core OAuth2 functionality including token generation,
// validation, and client management.
//
// Example:
//
//	facades := facades.New(adeleApp)
//	token, err := facades.GenerateOauthToken()
type Service struct {
	//Auth       *auth.Auth
	DB         *database.Database
	GrantTypes map[string]string
	Config     Configuration
	ErrorLog   *log.Logger
	Renderer   *render.Render
	Session    *scs.SessionManager
	Mux        *mux.Mux
}

// AuthorizationResponse represents the response from an authorization request.
// Used in authorization code and PKCE flows.
//
// Example:
//
//	response := &AuthorizationResponse{
//		Code:      "auth_code_123",
//		State:     "xyz",
//		TokenType: "code",
//	}
type AuthorizationResponse struct {
	GrantType   string      `json:"-"`
	TokenType   string      `json:"token_type"`
	Code        string      `json:"code"`
	State       string      `json:"state"`
	RedirectUri RedirectUri `json:redirectURL`
}

// OauthResponse represents the response from a token exchange request.
// Contains the access token and optionally a refresh token.
//
// Example:
//
//	// Response JSON:
//	// {
//	//   "token_type": "Bearer",
//	//   "access_token": "eyJhbGciOiJIUzI1NiIs...",
//	//   "refresh_token": "refresh_abc123",
//	//   "expires_in": 3600
//	// }
type OauthResponse struct {
	GrantType          string        `json:"-"`
	TokenType          string        `json:"token_type,omitempty"`
	ExpiresIn          time.Duration `json:"expires_in"`
	AccessToken        string        `json:"access_token,omitempty"`
	AuthorizationToken string        `json:"authorization_code,omitempty"`
	RefreshToken       string        `json:"refresh_token,omitempty"`
}

type AuthorizationToken struct {
	ID                  int       `db:"id,omitempty" json:"id"`
	UserID              *int      `db:"user_id,omitempty" json:"user_id"`
	ClientID            int       `db:"client_id" json:"client_id"`
	PlainText           string    `db:"token" json:"token"`
	Hash                []byte    `db:"token_hash" json:"-"`
	CreatedAt           time.Time `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time `db:"updated_at" json:"updated_at"`
	Expires             time.Time `db:"expiry" json:"expiry"`
	ChallengeCode       string    `db:"challenge_code,omitempty" json:"ChallengeCode"`
	ChallengeCodeMethod string    `db:"challenge_code_method,omitempty" json:"ChallengeCodeMethod"`
	State               string    `db:"-" json:"state"`
}

type OauthToken struct {
	ID           int       `db:"id,omitempty" json:"id"`
	UserID       *int      `db:"user_id,omitempty" json:"user_id"`
	ClientID     int       `db:"client_id" json:"client_id"`
	PlainText    string    `db:"token" json:"token"`
	Hash         []byte    `db:"token_hash" json:"-"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
	Expires      time.Time `db:"expiry" json:"expiry"`
	RefreshToken string    `db:"-" json:"refresh_token"`
	Scopes       string    `db:"scopes,omitempty" json:"scopes"`
}

type RefreshToken struct {
	ID            int       `db:"id,omitempty" json:"id"`
	AccessTokenID int       `db:"access_token_id" json:"-"`
	Expires       time.Time `db:"expiry" json:"expiry"`
	Hash          []byte    `db:"token_hash" json:"-"`
	PlainText     string    `db:"token" json:"token"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at" json:"updated_at"`
}

// Client represents an OAuth2 client application registered with the server.
// Supports multiple grant types: client_credentials, authorization_grant,
// authorization_grant_pkce, authorization_grant_pkce_implicit, and
// resource_owner_password_credentials.
//
// Example:
//
//	client := &Client{
//		Name:        "My App",
//		Secret:      "client_secret_here",
//		Type:        "client_credentials",
//		RedirectUrl: "https://myapp.com/callback",
//	}
type Client struct {
	ID          int       `db:"id,omitempty" json:"id"`
	UserID      *int      `db:"user_id,omitempty" json:"user_id"`
	Secret      string    `db:"secret" json:"secret"`
	Name        string    `db:"name"`
	Revoked     int       `db:"revoked"`
	Type        string    `db:"type"`
	RedirectUrl string    `db:"redirect_url,omitempty" json:"redirectURL"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// ErrorResponse represents an OAuth2 error response per RFC 6749.
//
// Example:
//
//	err := NewErrorResponse(ErrInvalidClient)
//	// Returns:
//	// {
//	//   "error": "invalid_client",
//	//   "description": "Client authentication failed",
//	//   "error_code": 401
//	// }
type ErrorResponse struct {
	Description string `json:"description"`
	Error       string `json:"error"`
	ErrorCode   int    `json:"error_code"`
	URI         string `json:"uri,omitempty"`
}

type RedirectUri struct {
	URI   string
	Path  string
	Query string
}

type User struct {
	ID        int        `db:"id,omitempty"`
	FirstName string     `db:"first_name"`
	LastName  string     `db:"last_name"`
	Email     string     `db:"email"`
	Active    int        `db:"user_active"`
	Password  string     `db:"password"`
	CreatedAt time.Time  `db:"created_at"`
	UpdatedAt time.Time  `db:"updated_at"`
	Token     OauthToken `db:"-"`
}
