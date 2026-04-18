package api

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cidekar/adele-framework"
	up "github.com/upper/db/v4"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
)

// Flow constants for authorization_code client sub-flows.
const (
	FlowPlain        = "plain"
	FlowPKCE         = "pkce"
	FlowPKCEImplicit = "pkce_implicit"
	FlowVerify       = "verify"
)

//go:embed templates
var templateFS embed.FS

// DB is the database session used for OAuth2 operations.
var DB up.Session

// extractClientCredentials extracts client_id and client_secret from the request.
// Checks Authorization: Basic header first (RFC 6749 §2.3.1), falls back to form body.
func extractClientCredentials(r *http.Request) (string, string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

// authErrorRedirect redirects to the client's redirect URI with error and state params
// per RFC 6749 §4.1.2.1. Used for authorization endpoint errors after client validation.
func authErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state string, oauthErr error) {
	q := url.Values{}
	q.Set("error", oauthErr.Error())
	q.Set("state", state)
	if desc, ok := Descriptions[oauthErr]; ok {
		q.Set("error_description", desc)
	}
	http.Redirect(w, r, redirectURI+"?"+q.Encode(), http.StatusFound)
}

// New creates a new Service instance with the given Adele application.
// It initializes the database session and loads configuration from config/oauth.yml.
//
// Example:
//
//	facades := facades.New(adeleApp)
//	// facades is now ready to handle OAuth2 operations
func New(a *adele.Adele) Service {
	o := newBase(a)

	// Load the configuration
	config, err := loadConfig(a)
	if err != nil {
		panic(err)
	}

	o.Config = *config
	setConfigDefaults(&o)

	return o
}

// NewWithConfig creates a new Service instance with a custom configuration.
// Used primarily for testing.
//
// Example:
//
//	config := facades.Configuration{Scopes: map[string]string{"read": "Read access"}}
//	facades := facades.NewWithConfig(adeleApp, config)
func NewWithConfig(a *adele.Adele, config Configuration) Service {
	o := newBase(a)
	o.Config = config
	setConfigDefaults(&o)
	return o
}

func newBase(a *adele.Adele) Service {
	o := Service{
		Renderer: a.Render,
		Mux:      a.Routes,
		Session:  a.Session,
	}

	// New Database session
	DB = a.DB.NewSession()

	return o
}

func setConfigDefaults(o *Service) {
	// set defaults for all token expiration windows
	if o.Config.AuthorizationTokenTTL == 0 {
		o.Config.AuthorizationTokenTTL = 60 * time.Minute
	}

	if o.Config.OauthTokenTTL == 0 {
		o.Config.OauthTokenTTL = 24 * time.Hour
	}

	if o.Config.RefreshTokenTokenTTL == 0 {
		o.Config.RefreshTokenTokenTTL = 24 * time.Hour
	}

	if o.Config.PkceImplicitTTL == 0 {
		o.Config.PkceImplicitTTL = 300 * time.Second
	}

	// Validate the scopes
	if o.Config.PkceImplicitAuthorizationScopes != nil {
		scopeStr, err := scopesMapToString(o.Config.PkceImplicitAuthorizationScopes)
		if err != nil {
			panic(err)
		}
		_, err = scopesValidate(scopeStr)
		if err != nil {
			panic(err)
		}
	}

	if o.Config.Scopes != nil {
		scopeStr, err := scopesMapToString(o.Config.Scopes)
		if err != nil {
			panic(err)
		}
		_, err = scopesValidate(scopeStr)
		if err != nil {
			panic(err)
		}
	}

}

func loadConfig(a *adele.Adele) (*Configuration, error) {
	// TODO: Move this into a command
	// Check for the configuration file in on the current system and create if not found at /config/oauth.yaml
	if _, err := os.Stat(a.RootPath + "/config/oauth.yml"); os.IsNotExist(err) {
		data, err := templateFS.ReadFile("templates/oauth.yml")
		if err != nil {
			return nil, fmt.Errorf("failed to read package oauth config from embedded file system: %v", err)
		}
		err = os.WriteFile(a.RootPath+"/config/oauth.yml", data, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write package oauth config to disk: %v", err)
		}
	}

	// Read the configuration file
	configFile, err := os.ReadFile(a.RootPath + "/config/oauth.yml")
	if err != nil {
		return nil, fmt.Errorf("failed to read oauth config file: %v", err)
	}

	// Unmarshal the JSON content into the struct
	var config Configuration
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}

// validateClientWithSecret authenticates a client by ID and secret.
// All code paths perform a bcrypt comparison to prevent timing-based enumeration.
func (o *Service) validateClientWithSecret(cid int, clientSecret string) (*Client, *ErrorResponse) {
	dummyHash := []byte("$2a$10$0000000000000000000000uGsOBFCBjMWmYFg0POnqGmGM.6FOrGK")

	client, err := o.GetClient(cid)

	// Always compare — real hash if client exists, dummy if not
	secret := dummyHash
	if client != nil && err == nil {
		secret = []byte(client.Secret)
	}
	secretErr := bcrypt.CompareHashAndPassword(secret, []byte(clientSecret))

	// Now evaluate all conditions uniformly
	if client == nil || err != nil || secretErr != nil || client.Revoked != 0 {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	return client, nil
}

// AuthorizationGrantExchange validates an authorization request and returns the redirect URI.
// This is the first step in the authorization code flow (GET request).
//
// Required form fields: client_id, grant_type, response_type, redirect_uri, state,
// code_challenge, code_challenge_method, scopes
//
// Example:
//
//	// GET /oauth/authorize?client_id=1&grant_type=authorization_code&response_type=code&
//	//     redirect_uri=https://app.com/callback&state=xyz&code_challenge=abc&
//	//     code_challenge_method=S256&scopes=read%20write
//
//	response, err := facades.AuthorizationGrantExchange(w, r)
//	if err != nil {
//		// Handle error
//	}
//	// Redirect to response.RedirectUri.URI
func (o *Service) AuthorizationGrantExchange(w http.ResponseWriter, r *http.Request) (*AuthorizationResponse, *ErrorResponse) {
	err := r.ParseForm()
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	requiredFields := []string{
		"client_id",
		"grant_type",
		"response_type",
		"redirect_uri",
		"state",
		"code_challenge",
		"code_challenge_method",
		"scopes",
	}

	// required
	for _, field := range requiredFields {
		if !r.Form.Has(field) {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	// not empty
	for _, field := range requiredFields {
		if strings.TrimSpace(r.Form.Get(field)) == "" {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	if r.Form.Get("grant_type") != "authorization_code" {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	if r.Form.Get("response_type") != "code" {
		return nil, NewErrorResponse(ErrUnsupportedResponseType)
	}

	if r.Form.Get("state") == "" {
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	// validate the client
	clientId := r.Form.Get("client_id")
	cid, err := strconv.Atoi(clientId)
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, err := o.GetClient(cid)
	if client == nil || err != nil || client.Revoked != 0 {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// client type supported by the method
	if client.Type != "authorization_code" {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}
	supportedFlows := []string{FlowPlain, FlowPKCE, FlowPKCEImplicit}
	if !slices.Contains(supportedFlows, client.Flow) {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// validate the client redirect uri matches the requested redirect uri
	ok := o.ValidateClientRedirect(r.Form.Get("redirect_uri"), client)
	if !ok {
		return nil, NewErrorResponse(ErrInvalidRedirectURI)
	}

	// validate challenge method and code
	_, err = ChallengeCodeValidate(r.Form.Get("code_challenge"), r.Form.Get("code_challenge_method"))
	if err != nil {
		authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), err)
		return nil, nil
	}

	// Validate the scopes
	ok, _ = scopesValidate(r.Form.Get("scopes"))
	if !ok {
		authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), ErrInvalidScope)
		return nil, nil
	}

	f := scopesFormat(r.Form.Get("scopes"))

	ok = o.scopesCanBeIssued(f)
	if !ok {
		authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), ErrInvalidScope)
		return nil, nil
	}

	// Generate CSRF token for the consent form
	csrfBytes := make([]byte, 32)
	rand.Read(csrfBytes)
	csrfToken := base64.URLEncoding.EncodeToString(csrfBytes)
	o.Session.Put(r.Context(), "oauth_csrf_token", csrfToken)

	response := AuthorizationResponse{
		RedirectUri: RedirectUri{
			Path:  r.URL.Path,
			Query: r.URL.RawQuery,
			URI:   fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery),
		},
		CSRFToken: csrfToken,
	}

	return &response, nil
}

// AuthorizationGrantExchangePost processes the authorization form submission.
// Handles plain, pkce, and pkce_implicit authorization code flows.
//
// Example:
//
//	// POST /oauth/authorize
//	// Content-Type: application/x-www-form-urlencoded
//	// client_id=1&grant_type=authorization_code&response_type=code&...
//
//	response, err := facades.AuthorizationGrantExchangePost(w, r)
//	if err != nil {
//		// Handle error
//	}
//	// For PKCE: redirect to response.RedirectUri.URI with code
//	// For implicit: return response with token
func (o *Service) AuthorizationGrantExchangePost(w http.ResponseWriter, r *http.Request) (*AuthorizationResponse, *ErrorResponse) {
	err := r.ParseForm()
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	// Validate CSRF token
	csrfToken := o.Session.GetString(r.Context(), "oauth_csrf_token")
	formCSRF := r.Form.Get("csrf_token")
	if csrfToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(formCSRF)) != 1 {
		return nil, NewErrorResponse(ErrInvalidRequest)
	}
	// Clear the CSRF token after use (single-use)
	o.Session.Remove(r.Context(), "oauth_csrf_token")

	// validate the request for all required fields and confirm values are provided for the field.
	requiredFields := []string{
		"client_id",
		"csrf_token",
		"grant_type",
		"response_type",
		"redirect_uri",
		"state",
		"code_challenge",
		"code_challenge_method",
		"scopes",
	}

	// required
	for _, field := range requiredFields {
		if !r.Form.Has(field) {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	// not empty
	for _, field := range requiredFields {
		if strings.TrimSpace(r.Form.Get(field)) == "" {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	if r.Form.Get("grant_type") != "authorization_code" {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// validate the client
	clientId := r.Form.Get("client_id")
	cid, err := strconv.Atoi(clientId)
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, err := o.GetClient(cid)
	if client == nil || err != nil || client.Revoked != 0 {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// client type supported by the method
	if client.Type != "authorization_code" {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}
	supportedFlows := []string{FlowPlain, FlowPKCE, FlowPKCEImplicit}
	if !slices.Contains(supportedFlows, client.Flow) {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	if !o.ValidateClientRedirect(r.Form.Get("redirect_uri"), client) {
		return nil, NewErrorResponse(ErrInvalidRedirectURI)
	}

	// validate the challenge code and method
	_, err = ChallengeCodeValidate(r.Form.Get("code_challenge"), r.Form.Get("code_challenge_method"))
	if err != nil {
		authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), err)
		return nil, nil
	}

	switch client.Flow {
	case FlowPlain:
		redirect, err := o.AuthorizationClientExchange(w, r, client)
		if err != nil {
			authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), errors.New(err.Error))
			return nil, nil
		}

		return redirect, nil
	case FlowPKCE:
		redirect, err := o.AuthorizationClientCodeExchange(w, r, client)
		if err != nil {
			authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), errors.New(err.Error))
			return nil, nil
		}

		return redirect, nil
	case FlowPKCEImplicit:
		auth, err := o.AuthorizationClientCodeExchangeImplicit(w, r, client)
		if err != nil {
			authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), errors.New(err.Error))
			return nil, nil
		}

		return auth, nil
	default:
		authErrorRedirect(w, r, r.Form.Get("redirect_uri"), r.Form.Get("state"), ErrInvalidClient)
		return nil, nil
	}
}

// AccessTokenGrantExchange exchanges credentials for an access token.
// Supports client_credentials, password, and authorization_code (PKCE code exchange) grant types.
//
// Example (client_credentials):
//
//	// POST /oauth/token
//	// Content-Type: application/x-www-form-urlencoded
//	// client_id=1&client_secret=secret&grant_type=client_credentials&scopes=read
//
// Example (PKCE code exchange):
//
//	// POST /oauth/token
//	// client_id=1&code=auth_code&code_verifier=verifier&
//	// code_challenge_method=S256&grant_type=authorization_code&scopes=read
//
//	response, err := facades.AccessTokenGrantExchange(w, r)
//	// response.AccessToken contains the bearer token
//	// response.RefreshToken contains the refresh token (if applicable)
func (o *Service) AccessTokenGrantExchange(w http.ResponseWriter, r *http.Request) (*OauthResponse, *ErrorResponse) {
	err := r.ParseForm()
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	// handle authorization grant pkce and authorization grant pkce implicit code exchange
	if r.Form.Has("code") && r.Form.Has("code_verifier") && r.Form.Has("code_challenge_method") {
		requiredFields := []string{
			"client_id",
			"code",
			"code_verifier",
			"code_challenge_method",
			"grant_type",
			"scopes",
		}

		// required
		for _, field := range requiredFields {
			if !r.Form.Has(field) {
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}

		// not empty
		for _, field := range requiredFields {
			if strings.TrimSpace(r.Form.Get(field)) == "" {
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}

		// validate the client
		clientId := r.Form.Get("client_id")
		cid, err := strconv.Atoi(clientId)
		if err != nil {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		client, err := o.GetClient(cid)
		if client == nil || err != nil || client.Revoked != 0 {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// validate client is a supported client for the workflow
		if client.Type != "authorization_code" {
			return nil, NewErrorResponse(ErrInvalidClient)
		}
		if !slices.Contains([]string{FlowPKCE, FlowPKCEImplicit}, client.Flow) {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// The validation here is a bit different for the code exchange. The code_challenge and code challenge_method are used to verify
		// 1. look up the authorization token by code in the db
		authorizationToken, err := o.ConsumeAuthorizationToken(r.Form.Get("code"))
		if err != nil {
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		// 2. Validate client provided code challenge
		ok := o.VerifyAuthorizationCode(*authorizationToken, r.Form.Get("code_verifier"))
		if !ok {
			return nil, NewErrorResponse(ErrInvalidCodeChallenge)
		}

		// 3. does the token challenge code method match the provided code_challenge_method
		if authorizationToken.ChallengeCodeMethod != r.Form.Get("code_challenge_method") {
			return nil, NewErrorResponse(ErrInvalidCodeChallenge)
		}

		// 4. was it issued to the client that is making the request?
		if strconv.Itoa(authorizationToken.ClientID) != r.Form.Get("client_id") {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// 5. is the authorization token expired?
		ok = o.TokenIsExpired(authorizationToken)
		if !ok {
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		// At this point we are good to issue access and refresh tokens for the client. If this request is for a pkce_implicit client, only generate an access token, otherwise generate both an access and refresh token.

		// access token
		accessToken, err := o.GenerateOauthToken()
		if err != nil {
			o.ErrorLog.Println(err)
			return nil, NewErrorResponse(ErrServerError)
		}

		accessToken.ClientID = client.ID

		// validate the scope provided by the client are a string of alpha-numeric characters separated with whitespaces
		ok, _ = scopesValidate(r.Form.Get("scopes"))
		if !ok {
			return nil, NewErrorResponse(ErrInvalidScope)
		}

		ok = o.scopesCanBeIssued(scopesFormat(r.Form.Get("scopes")))
		if !ok {
			return nil, NewErrorResponse(ErrInvalidScope)
		}

		// We need to check if the scopes can be issued to the client
		if client.Flow == FlowPKCE {
			accessToken.UserID = authorizationToken.UserID

			ok, _ := scopesValidate(r.Form.Get("scopes"))
			if !ok {
				return nil, NewErrorResponse(ErrInvalidScope)
			}

			f := scopesFormat(r.Form.Get("scopes"))
			ok = o.scopesCanBeIssued(f)
			if !ok {
				return nil, NewErrorResponse(ErrInvalidScope)
			}

			accessToken.Scopes = strings.Join(f, " ")
		}

		if client.Flow == FlowPKCEImplicit {

			// can the scopes be issues to the client by the Authorization Sever?
			ok, _ := scopesValidate(r.Form.Get("scopes"))
			if !ok {
				return nil, NewErrorResponse(ErrInvalidScope)
			}

			f := scopesFormat(r.Form.Get("scopes"))
			ok = o.scopesCanBeIssued(f)
			if !ok {
				return nil, NewErrorResponse(ErrInvalidScope)
			}

			// are the scopes whitelisted to be issued to the client?
			for _, scope := range f {
				_, ok := o.Config.PkceImplicitAuthorizationScopes[scope]
				if !ok {
					return nil, NewErrorResponse(ErrInvalidScope)
				}
			}

			accessToken.Scopes = strings.Join(f, " ")

			accessToken.Expires = time.Now().UTC().Add(o.Config.PkceImplicitTTL)
		}

		_, err = o.InsertOauthToken(accessToken)

		if err != nil {
			o.ErrorLog.Println(err)
			return nil, NewErrorResponse(ErrServerError)
		}

		if client.Flow == FlowPKCE {
			// Generate a refresh token that can be used when the current access token becomes invalid or expires.
			refreshToken, err := o.GenerateRefreshToken(*authorizationToken.UserID, accessToken.ID, client.ID)
			if err != nil {
				o.ErrorLog.Println(err)
				return nil, NewErrorResponse(ErrServerError)
			}

			// Persist the refresh token
			err = o.InsertRefreshToken(refreshToken)
			if err != nil {
				o.ErrorLog.Println(err)
				return nil, NewErrorResponse(ErrServerError)
			}

			response := OauthResponse{
				GrantType:    "authorization_code",
				TokenType:    "Bearer",
				ExpiresIn:    int64(time.Until(accessToken.Expires).Seconds()),
				AccessToken:  accessToken.PlainText,
				RefreshToken: refreshToken.PlainText,
				Scope:        accessToken.Scopes,
			}
			return &response, nil
		}

		response := OauthResponse{
			GrantType:   "authorization_code",
			TokenType:   "Bearer",
			ExpiresIn:   int64(time.Until(accessToken.Expires).Seconds()),
			AccessToken: accessToken.PlainText,
			Scope:       accessToken.Scopes,
		}
		return &response, nil
	}

	// Handle exchange for other grant types
	// check the request for all required fields and confirm values are provided for the field.
	requiredFields := []string{
		"grant_type",
		"scopes",
	}

	if r.Form.Get("grant_type") == "password" {
		requiredFields = append(requiredFields, "username", "password")
	}

	// required
	for _, field := range requiredFields {
		if !r.Form.Has(field) {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	// not empty
	for _, field := range requiredFields {
		if strings.TrimSpace(r.Form.Get(field)) == "" {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	var supportedGrantTypes = []string{
		"client_credentials",
		"password",
	}
	isSupportedGrant := false
	for _, grantType := range supportedGrantTypes {
		if r.Form.Get("grant_type") == grantType {
			isSupportedGrant = true
			break
		}
	}

	if !isSupportedGrant {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// validate the client
	clientId, clientSecret := extractClientCredentials(r)
	if clientId == "" || clientSecret == "" {
		return nil, NewErrorResponse(ErrInvalidClient)
	}
	cid, err := strconv.Atoi(clientId)
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, errRes := o.validateClientWithSecret(cid, clientSecret)
	if errRes != nil {
		return nil, errRes
	}

	if client.Type != r.Form.Get("grant_type") {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// Client Credentials
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
	if r.Form.Get("grant_type") == "client_credentials" {

		token, err := o.GenerateOauthToken()
		if err != nil {
			o.ErrorLog.Println(err)
			return nil, NewErrorResponse(ErrServerError)
		}

		token.ClientID = client.ID

		ok, _ := scopesValidate(r.Form.Get("scopes"))
		if !ok {
			return nil, NewErrorResponse(ErrInvalidScope)
		}

		f := scopesFormat(r.Form.Get("scopes"))

		ok = o.scopesCanBeIssued(f)
		if !ok {
			return nil, NewErrorResponse(ErrInvalidScope)
		}

		token.Scopes = strings.Join(f, " ")

		_, err = o.InsertOauthToken(token)

		if err != nil {
			o.ErrorLog.Println(err)
			return nil, NewErrorResponse(ErrServerError)
		}

		response := OauthResponse{
			GrantType:   "client_credentials",
			TokenType:   "Bearer",
			ExpiresIn:   int64(time.Until(token.Expires).Seconds()),
			AccessToken: token.PlainText,
			Scope:       token.Scopes,
		}
		return &response, nil
	}

	// Resource Owner Password Credentials
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
	if r.Form.Get("grant_type") == "password" {
		requiredFields := []string{
			"username",
			"password",
		}

		// required
		for _, field := range requiredFields {
			if !r.Form.Has(field) {
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}

		// not empty
		notEmptyFields := []string{
			"username",
			"password",
		}
		for _, field := range notEmptyFields {
			if strings.TrimSpace(r.Form.Get(field)) == "" {
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}

		token, refreshToken, err := o.ResourceOwnerTokenExchange(r, w, *client)
		if err != nil {
			return nil, err
		}

		response := OauthResponse{
			GrantType:    "password",
			TokenType:    "Bearer",
			ExpiresIn:    int64(time.Until(token.Expires).Seconds()),
			AccessToken:  token.PlainText,
			RefreshToken: refreshToken.PlainText,
			Scope:        token.Scopes,
		}
		return &response, nil
	}

	return nil, NewErrorResponse(ErrUnsupportedGrantType)
}

// RefreshTokenExchange exchanges a valid refresh token for a new access token.
// Per RFC 6749, the new token's scopes must be a subset of the original token's scopes.
//
// Required fields: client_id, client_secret, grant_type (must be "refresh_token"),
// refresh_token, scopes
//
// Example:
//
//	// POST /oauth/token/refresh
//	// Content-Type: application/x-www-form-urlencoded
//	// client_id=1&client_secret=secret&grant_type=refresh_token&
//	// refresh_token=abc123&scopes=read
//
//	response, err := facades.RefreshTokenExchange(w, r)
//	// response.AccessToken = new access token
//	// response.RefreshToken = new refresh token
func (o *Service) RefreshTokenExchange(w http.ResponseWriter, r *http.Request) (*OauthResponse, *ErrorResponse) {
	err := r.ParseForm()
	if err != nil {
		return nil, NewErrorResponse(ErrServerError)
	}

	// Per RFC 6749 require client authentication for confidential clients or for any client that was issued client credentials
	requiredFields := []string{
		"grant_type",
		"scopes",
		"refresh_token",
	}

	// required
	for _, field := range requiredFields {
		if !r.Form.Has(field) {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	// not empty
	notEmptyFields := []string{
		"grant_type",
		"refresh_token",
	}
	for _, field := range notEmptyFields {
		if strings.TrimSpace(r.Form.Get(field)) == "" {
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	if r.Form.Get("grant_type") != "refresh_token" {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// authenticate the client
	clientId, clientSecret := extractClientCredentials(r)
	if clientId == "" || clientSecret == "" {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	cid, err := strconv.Atoi(clientId)
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, errRes := o.validateClientWithSecret(cid, clientSecret)
	if errRes != nil {
		return nil, errRes
	}

	// validate the refresh_token
	rt, err := o.GetRefreshByToken(r.Form.Get("refresh_token"))
	if err != nil || rt == nil {
		return nil, NewErrorResponse(ErrInvalidRefreshToken)
	}

	// ensure that the refresh token was issued to the authenticated client
	at, err := o.GetOauthToken(rt.AccessTokenID)
	if err != nil || at == nil {
		return nil, NewErrorResponse(ErrInvalidRefreshToken)
	}

	requestClientID, err := strconv.Atoi(r.Form.Get("client_id"))
	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if at.ClientID != requestClientID {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// Is the refresh token expired?
	ok := o.TokenIsExpired(rt)
	if !ok {
		return nil, NewErrorResponse(ErrExpiredRefreshToken)
	}

	// validate the scopes provided are formatted properly
	ok, _ = scopesValidate(r.Form.Get("scopes"))
	if !ok {
		return nil, NewErrorResponse(ErrInvalidScope)
	}

	// RFC 6749 defines a request to refresh may not contain a scope that is not already assigned to the access token
	scopesMap := scopesFormat(r.Form.Get("scopes"))
	if scopesMap != nil {
		existingScopes := strings.Split(at.Scopes, " ")
		for _, scope := range scopesMap {
			if !slices.Contains(existingScopes, scope) {
				return nil, NewErrorResponse(ErrInvalidScope)
			}
		}
	}

	err = o.DeleteOauthToken(at.ID)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, NewErrorResponse(ErrServerError)
	}

	err = o.DeleteRefreshTokenByToken(rt.PlainText)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, NewErrorResponse(ErrServerError)
	}

	// Generate new access token and refresh token and return them to the client
	accessToken, err := o.GenerateOauthToken()
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, NewErrorResponse(ErrServerError)
	}

	accessToken.ClientID = client.ID
	accessToken.UserID = at.UserID
	accessToken.Scopes = strings.Join(scopesMap, " ")
	accessToken, err = o.InsertOauthToken(accessToken)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, NewErrorResponse(ErrServerError)
	}

	refreshToken, err := o.GenerateRefreshToken(*accessToken.UserID, accessToken.ID, accessToken.ClientID)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, NewErrorResponse(ErrServerError)
	}

	// Persist the refresh token
	err = o.InsertRefreshToken(refreshToken)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, NewErrorResponse(ErrServerError)
	}

	response := OauthResponse{
		GrantType:    "refresh_token",
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(accessToken.Expires).Seconds()),
		AccessToken:  accessToken.PlainText,
		RefreshToken: refreshToken.PlainText,
		Scope:        accessToken.Scopes,
	}
	return &response, nil

}
