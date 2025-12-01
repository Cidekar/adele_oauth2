package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/harrisonde/oauth/api"

	"github.com/CloudyKit/jet/v6"
)

// AuthorizationGrantExchange renders the login form for the user to enter their credentials.
// This is the first step in the authorization code flow.
//
// Example:
//
//	// Register as a route handler
//	router.Get("/oauth/authorize", handlers.AuthorizationGrantExchange)
//
//	// Request:
//	// GET /oauth/authorize?client_id=123&response_type=code&redirect_uri=https://app.com/callback
func (h *Handlers) AuthorizationGrantExchange(w http.ResponseWriter, r *http.Request) {

	var response *api.AuthorizationResponse
	var err *api.ErrorResponse

	response, err = h.Api.AuthorizationGrantExchange(w, r)

	if err != nil {
		vars := make(jet.VarMap)
		vars.Set("validatorBag", err.Description)

		h.App.Helpers.Render(w, r, "invalid", vars, nil)
		return
	}

	vars := make(jet.VarMap)
	vars.Set("url", response.RedirectUri.URI)
	h.App.Render.Page(w, r, "login", vars, nil)
}

// AuthorizationGrantExchangePost processes the login form submission and completes the authorization.
// Handles authorization_grant, authorization_grant_pkce, and authorization_grant_pkce_implicit flows.
//
// Example:
//
//	// Register as a route handler
//	router.Post("/oauth/authorize", handlers.AuthorizationGrantExchangePost)
//
//	// Request (form data):
//	// POST /oauth/authorize
//	// Content-Type: application/x-www-form-urlencoded
//	// client_id=123&grant_type=authorization_code&response_type=code&code_challenge=abc123
func (h *Handlers) AuthorizationGrantExchangePost(w http.ResponseWriter, r *http.Request) {
	var response *api.AuthorizationResponse
	var err *api.ErrorResponse

	response, err = h.Api.AuthorizationGrantExchangePost(w, r)
	if err != nil {
		if r.Header.Get("Accept") == "application/json" {
			h.App.Helpers.WriteJSON(w, err.ErrorCode, err)
			return
		}

		vars := make(jet.VarMap)
		vars.Set("validatorBag", err.Description)
		if err.ErrorCode == 400 {
			h.App.Helpers.Render(w, r, "login", vars, nil)
			return
		}

		h.App.Helpers.Render(w, r, "invalid", vars, nil)
		return
	}

	// flow may render internal view for user to confirm access
	if response.GrantType == "authorization_grant_verify" {
		return
	}

	if response.GrantType == "authorization_grant_pkce" {
		if response.RedirectUri.URI != "" {
			http.Redirect(w, r, response.RedirectUri.URI, http.StatusFound)
			return
		}

	} else if response.GrantType == "authorization_grant_pkce_implicit" {
		if response.TokenType == "code" {
			h.App.Helpers.WriteJSON(w, http.StatusOK, response, nil)
			return
		}
	}
}

// AccessTokenGrantExchange exchanges client credentials or authorization codes for an access token.
// Supports client_credentials, authorization_code, and PKCE grant types.
//
// Example:
//
//	// Register as a route handler
//	router.Post("/oauth/token", handlers.AccessTokenGrantExchange)
//
//	// Request for client_credentials:
//	// POST /oauth/token
//	// Content-Type: application/x-www-form-urlencoded
//	// Accept: application/json
//	// client_id=123&client_secret=secret&grant_type=client_credentials&scopes=read write
//
//	// Response:
//	// {
//	//   "token_type": "Bearer",
//	//   "access_token": "eyJhbGciOiJIUzI1NiIs...",
//	//   "expires_in": 3600
//	// }
func (h *Handlers) AccessTokenGrantExchange(w http.ResponseWriter, r *http.Request) {
	var response *api.OauthResponse
	var err *api.ErrorResponse
	response, err = h.Api.AccessTokenGrantExchange(w, r)

	fmt.Println(r.Header.Get("Accept"))
	if err != nil {
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			h.App.Helpers.WriteJSON(w, err.ErrorCode, err)
			return
		}

		vars := make(jet.VarMap)
		vars.Set("validatorBag", err.Description)
		h.App.Helpers.Render(w, r, "login", vars, nil)
		return
	}

	h.App.Helpers.WriteJSON(w, http.StatusOK, response)
}

// RefreshTokenExchange exchanges a refresh token for a new access token.
// The refresh token must be valid and not expired.
//
// Example:
//
//	// Register as a route handler
//	router.Post("/oauth/token/refresh", handlers.RefreshTokenExchange)
//
//	// Request:
//	// POST /oauth/token/refresh
//	// Content-Type: application/x-www-form-urlencoded
//	// Accept: application/json
//	// client_id=123&client_secret=secret&grant_type=refresh_token&refresh_token=abc123&scopes=read
//
//	// Response:
//	// {
//	//   "token_type": "Bearer",
//	//   "access_token": "eyJhbGciOiJIUzI1NiIs...",
//	//   "refresh_token": "new_refresh_token...",
//	//   "expires_in": 3600
//	// }
func (h *Handlers) RefreshTokenExchange(w http.ResponseWriter, r *http.Request) {
	var response *api.OauthResponse
	var err *api.ErrorResponse

	response, err = h.Api.RefreshTokenExchange(w, r)
	if err != nil {
		if r.Header.Get("Accept") == "application/json" {
			h.App.Helpers.WriteJSON(w, err.ErrorCode, err)
			return
		}

		vars := make(jet.VarMap)
		vars.Set("validatorBag", err.Description)
		h.App.Helpers.Render(w, r, "login", vars, nil)
		return
	}

	h.App.Helpers.WriteJSON(w, http.StatusOK, response)
}
