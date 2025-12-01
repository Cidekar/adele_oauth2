package handlers

import (
	"github.com/harrisonde/oauth/api"

	"github.com/cidekar/adele-framework"
)

// Handlers contains HTTP handlers for OAuth2 endpoints.
// It requires an Adele application instance and OAuth2 facades for processing requests.
//
// Example:
//
//	handlers := &Handlers{
//		App: adeleApp,
//		Api: oauthFacades,
//	}
//	http.HandleFunc("/oauth/token", handlers.AccessTokenGrantExchange)
type Handlers struct {
	App *adele.Adele
	Api *api.Service
}
