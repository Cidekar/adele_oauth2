package middleware

import (
	"github.com/harrisonde/oauth/api"
	"github.com/harrisonde/oauth/data"

	"github.com/cidekar/adele-framework"
)

// Middleware provides OAuth2 middleware functions for protecting routes.
// It validates access tokens and checks scopes for authorization.
//
// Example:
//
//	middleware := &Middleware{
//		App:    adeleApp,
//		Api:    oauthFacades,
//		Models: data.Models{Tokens: &data.Token{Upper: db}},
//	}
//
//	// Apply to routes
//	router.Use(middleware.AuthToken)
//	router.Use(middleware.CheckScopes)
type Middleware struct {
	App    *adele.Adele
	Api    *api.Service
	Models data.Models
}
