package oauth

import (
	"encoding/json"
	"net/http"
	"time"

	adele "github.com/cidekar/adele-framework"
	"github.com/cidekar/adele-framework/provider"
	"github.com/cidekar/adele-oauth2/api"
)

// ServiceProvider is the compiled Adele framework provider for OAuth2.
// It registers token exchange routes and wires up the OAuth2 service.
//
// Example:
//
//	// Registered automatically via init(); access after boot:
//	p := app.GetProvider("oauth").(*oauth.ServiceProvider)
type ServiceProvider struct {
	service   *api.Service
	config    api.Configuration
	hasConfig bool
}

// Name returns the unique identifier for this provider.
func (p *ServiceProvider) Name() string {
	return "oauth"
}

// Priority returns 51, placing this provider in the security tier per Adele conventions.
func (p *ServiceProvider) Priority() int {
	return 51
}

// Configure maps a config map to the Configuration struct fields and stores it
// for use during Register.
func (p *ServiceProvider) Configure(config map[string]interface{}) error {
	if scopes, ok := config["scopes"].(map[string]string); ok {
		p.config.Scopes = scopes
	}
	if guardedRoutes, ok := config["guarded_route_groups"].([]string); ok {
		p.config.GuardedRouteGroups = guardedRoutes
	}
	if unguardedRoutes, ok := config["unguarded_routes"].([]string); ok {
		p.config.UnguardedRoutes = unguardedRoutes
	}
	if pkceScopes, ok := config["pkce_implicit_authorization_scopes"].(map[string]string); ok {
		p.config.PkceImplicitAuthorizationScopes = pkceScopes
	}
	if authTTL, ok := config["authorization_token_ttl"].(time.Duration); ok {
		p.config.AuthorizationTokenTTL = authTTL
	}
	if oauthTTL, ok := config["oauth_token_ttl"].(time.Duration); ok {
		p.config.OauthTokenTTL = oauthTTL
	}
	if pkceTTL, ok := config["pkce_implicit_ttl"].(time.Duration); ok {
		p.config.PkceImplicitTTL = pkceTTL
	}
	if refreshTTL, ok := config["refresh_token_ttl"].(time.Duration); ok {
		p.config.RefreshTokenTokenTTL = refreshTTL
	}
	if verifyPath, ok := config["verify_template_path"].(string); ok {
		p.config.VerifyTemplatePath = verifyPath
	}
	p.hasConfig = true
	return nil
}

// Register initializes the OAuth2 service and registers token routes on the Adele app.
func (p *ServiceProvider) Register(app interface{}) error {
	a := app.(*adele.Adele)

	var svc api.Service
	if p.hasConfig {
		svc = api.NewWithConfig(a, p.config)
	} else {
		svc = api.New(a)
	}
	p.service = &svc

	a.Routes.Post("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		res, errRes := p.service.AccessTokenGrantExchange(w, r)
		if errRes != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(errRes.ErrorCode)
			json.NewEncoder(w).Encode(errRes)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	})

	a.Routes.Post("/oauth/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		res, errRes := p.service.RefreshTokenExchange(w, r)
		if errRes != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(errRes.ErrorCode)
			json.NewEncoder(w).Encode(errRes)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	})

	a.Routes.Get("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		res, errRes := p.service.AuthorizationGrantExchange(w, r)
		if errRes != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(errRes.ErrorCode)
			json.NewEncoder(w).Encode(errRes)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	})

	a.Routes.Post("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		res, errRes := p.service.AuthorizationGrantExchangePost(w, r)
		if errRes != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(errRes.ErrorCode)
			json.NewEncoder(w).Encode(errRes)
			return
		}
		if res == nil {
			return // redirect already written by service
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	})

	// Test route for bearer middleware validation
	a.Routes.Get("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "pong"})
	})

	return nil
}

// Boot is a no-op; all initialization is done in Register.
func (p *ServiceProvider) Boot(app interface{}) error {
	return nil
}

func init() {
	provider.RegisterGlobalProvider(&ServiceProvider{})
}
