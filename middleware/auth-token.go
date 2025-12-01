package middleware

import (
	"context"
	"net/http"

	"github.com/harrisonde/oauth/api"
	"github.com/harrisonde/oauth/data"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// accessTokenKey is the context key used to store the access token.
const accessTokenKey contextKey = "accessToken"

// AuthToken is middleware that validates OAuth2 bearer tokens from the Authorization header.
// It skips authentication for routes defined in data.UnguardedRoutes.
// On success, it stores the access token in the request context for downstream handlers.
//
// Example:
//
//	// Apply to all routes in a group
//	router.Route("/api", func(r chi.Router) {
//		r.Use(middleware.AuthToken)
//		r.Get("/users", usersHandler)
//	})
//
//	// Request must include:
//	// Authorization: Bearer <access_token>
//	// Accept: application/json
//
//	// Access token in handler:
//	token := r.Context().Value(accessTokenKey).(string)
func (m *Middleware) AuthToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		header := r.Header.Get("Accept")
		if header != "application/json" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		unguardedRoutes := data.UnguardedRoutes

		unguarded := false
		for _, route := range unguardedRoutes {
			if r.URL.Path == route {
				unguarded = true
				break
			}
		}

		if unguarded {
			next.ServeHTTP(w, r)
			return

		}

		_, err := m.Models.Tokens.AuthenticateToken(r)
		if err != nil {
			m.App.Log.Error(err)

			payload := api.NewErrorResponse(api.ErrInvalidClient)
			_ = m.App.Helpers.WriteJSON(w, api.StatusCodes[api.ErrInvalidClient], payload)
			return
		}

		// Add the token scopes to the context
		token, err := m.Models.Tokens.GetAuthTokenFromHeader(r)
		if err != nil {
			m.App.Log.Error(err)
			payload := api.NewErrorResponse(api.ErrInvalidClient)
			_ = m.App.Helpers.WriteJSON(w, api.StatusCodes[api.ErrInvalidClient], payload)
			return
		}

		ctx := context.WithValue(r.Context(), accessTokenKey, token.PlainText)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
