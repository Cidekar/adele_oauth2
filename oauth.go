package oauth

import (
	"github.com/harrisonde/oauth/api"
	"github.com/harrisonde/oauth/handlers"
	"github.com/harrisonde/oauth/middleware"

	"github.com/cidekar/adele-framework"
	"github.com/cidekar/adele-framework/provider"
)

// OauthProvider is the main provider for OAuth2 authentication services.
// It manages facades, handlers, and middleware for OAuth2 token operations.
//
// Example:
//
//	// The provider is automatically registered via init()
//	// Access it from your Adele app after boot:
//	provider := app.GetProvider("oauth").(*oauth.OauthProvider)
type OauthProvider struct {
	Service    *api.Service
	Handlers   *handlers.Handlers
	Middleware *middleware.Middleware
	greeting   string
}

// Name returns the unique identifier for this provider.
//
// Example:
//
//	provider := &OauthProvider{}
//	name := provider.Name() // returns "oauth"
func (p *OauthProvider) Name() string {
	return "oauth"
}

// Register initializes the OAuth2 provider and registers routes with the Adele application.
// This method is called automatically by the Adele framework during application startup.
//
// Example:
//
//	// Called automatically by Adele framework
//	// Registers the following routes:
//	// POST /oauth/token - Exchange credentials for access token
//	// POST /oauth/token/refresh - Refresh an existing token
func (p *OauthProvider) Register(app interface{}) error {

	a := app.(*adele.Adele)

	// Initialize here instead
	svc := api.New(a)
	p.Service = &svc
	p.Handlers = &handlers.Handlers{App: a, Api: p.Service}
	p.Middleware = &middleware.Middleware{App: a, Api: p.Service}

	// Register routes
	a.Routes.Post("/oauth/token", p.Handlers.AccessTokenGrantExchange)
	a.Routes.Post("/oauth/token/refresh", p.Handlers.RefreshTokenExchange)

	return nil
}

// Boot performs any boot-time initialization after all providers have been registered.
// This method is called automatically by the Adele framework.
//
// Example:
//
//	// Called automatically after Register()
//	// Use for initialization that depends on other providers being registered
func (p *OauthProvider) Boot(app interface{}) error {
	return nil
}

func init() {
	provider.RegisterGlobalProvider(&OauthProvider{
		greeting: "Hello, World!",
	})
}
