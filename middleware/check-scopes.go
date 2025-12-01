package middleware

import (
	"net/http"
	"slices"
	"strings"

	"github.com/harrisonde/oauth/api"
)

// CheckScopes validates that the access token in the request context has the required scopes
// to access the requested resource. Scopes are defined per-route in the router configuration.
//
// Example:
//
//	// Apply after AuthToken middleware
//	router.Route("/api", func(r chi.Router) {
//		r.Use(middleware.AuthToken)
//		r.Use(middleware.CheckScopes)
//		r.Get("/users", usersHandler)  // Requires scopes defined for /api/users
//	})
//
//	// Define route scopes in router:
//	router.WithScopes("/api/users", []string{"users:read"})
//
//	// Token must have matching scopes or request returns 403 Forbidden
func (m *Middleware) CheckScopes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tid, ok := r.Context().Value("accessToken").(string)
		if !ok {
			payload := api.NewErrorResponse(api.ErrAccessDenied)
			_ = m.App.Helpers.WriteJSON(w, api.StatusCodes[api.ErrAccessDenied], payload)
			return
		}

		token, err := m.Models.Tokens.GetByToken(tid)
		if err != nil {
			payload := api.NewErrorResponse(api.ErrAccessDenied)
			_ = m.App.Helpers.WriteJSON(w, api.StatusCodes[api.ErrAccessDenied], payload)
			return
		}

		muxRouteScope := m.App.Routes.GetScopes(r.URL.Path)

		if len(muxRouteScope.Scope) != 0 {
			for _, s := range muxRouteScope.Scope {
				if !slices.Contains(strings.Split(token.Scopes, " "), strings.TrimSpace(s)) {
					payload := api.NewErrorResponse(api.ErrAccessDenied)
					_ = m.App.Helpers.WriteJSON(w, api.StatusCodes[api.ErrAccessDenied], payload)
					return
				}
			}
		}

		next.ServeHTTP(w, r)

	})
}
