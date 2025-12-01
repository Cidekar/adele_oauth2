package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
)

func (o *Service) AuthenticationTokenMiddleware() func(next http.Handler) http.Handler {
	return BearerTokenHandler(o.Config.UnguardedRoutes, o.Config.GuardedRouteGroups, o.ErrorLog, o)
}

func (o *Service) AuthenticationCheckForScopes() func(next http.Handler) http.Handler {
	return ScopeHandler(o.Config.UnguardedRoutes, o.Config.GuardedRouteGroups, o.ErrorLog, o)
}

// authenticate the bearer token attached to a HTTP request is a valid token by getting it by the plain text value from the db and checking that is not expired. Valid tokens are added to the context of the request as an access token for use by other middleware deeper in the stack. The middleware is designed for use in the global stack, so it is going to get loaded on every request, as a result the  the guarded route groups are first checked and quickly passed to the next middleware if the path is not in a guarded group.
func BearerTokenHandler(unguardedRoute []string, GuardedRouteGroups []string, ErrorLogger *log.Logger, o *Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			if len(GuardedRouteGroups) == 0 {
				panic("no guarded routes were specified in the oauth config")
			}

			if !isProtectedBaseRoute(r.URL.Path, GuardedRouteGroups) {
				next.ServeHTTP(w, r)
				return
			}

			fmt.Println(1)
			unguarded := false
			for _, route := range unguardedRoute {
				if r.URL.Path == route {
					unguarded = true
					break
				}
			}

			fmt.Println(2)
			if unguarded {
				next.ServeHTTP(w, r)
				return
			}

			fmt.Println(3)

			header := r.Header.Get("Accept")
			if header != "application/json" {
				fmt.Println("oops")
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			fmt.Println(4)

			ok, token, err := o.AuthenticateToken(r)
			if err != nil {
				err := writeJSON(w, StatusCodes[ErrInvalidClient], Descriptions[ErrInvalidClient])
				if err != nil {
					ErrorLogger.Println(err)
					return
				}
				return
			}

			fmt.Println(5)
			if !ok {
				err := writeJSON(w, StatusCodes[ErrInvalidClient], Descriptions[ErrInvalidClient])
				if err != nil {
					ErrorLogger.Println(err)
					return
				}
				return
			}

			ctx := context.WithValue(r.Context(), "accessToken", token.PlainText)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// write a JSON response to the client
func writeJSON(w http.ResponseWriter, status int, data interface{}) error {
	out, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	if err != nil {
		return err
	}
	return nil
}

// check if the path is part of a protected route group set in the configuration
func isProtectedBaseRoute(path string, groups []string) bool {
	for _, route := range groups {
		if !strings.Contains(path, route) {
			return false
		}
	}
	return true
}

// look up the scopes assigned to the current route and confirm the access token passed in the http request has the same scopes assigned to the token.
func ScopeHandler(UnguardedRoutes []string, GuardedRouteGroups []string, ErrorLogger *log.Logger, o *Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			if !isProtectedBaseRoute(r.URL.Path, GuardedRouteGroups) {
				next.ServeHTTP(w, r)
				return
			}

			for _, route := range UnguardedRoutes {
				if r.URL.Path == route {
					next.ServeHTTP(w, r)
					return
				}
			}

			tid, ok := r.Context().Value("accessToken").(string)
			if !ok {
				err := writeJSON(w, StatusCodes[ErrAccessDenied], Descriptions[ErrAccessDenied])
				if err != nil {
					ErrorLogger.Println(err)
					return
				}
				return
			}

			token, err := o.GetByToken(tid)
			if err != nil {
				err := writeJSON(w, StatusCodes[ErrAccessDenied], Descriptions[ErrAccessDenied])
				if err != nil {
					ErrorLogger.Println(err)
					return
				}
				return
			}

			muxRouteScope := o.Mux.GetScopes(r.URL.Path)
			if len(muxRouteScope.Scope) != 0 {
				for _, s := range muxRouteScope.Scope {
					if !slices.Contains(strings.Split(token.Scopes, " "), strings.TrimSpace(s)) {
						err := writeJSON(w, StatusCodes[ErrAccessDenied], Descriptions[ErrAccessDenied])
						if err != nil {
							ErrorLogger.Println(err)
							return
						}
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
