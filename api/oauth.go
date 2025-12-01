package api

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cidekar/adele-framework"
	up "github.com/upper/db/v4"
	"gopkg.in/yaml.v2"
)

// DB is the database session used for OAuth2 operations.
var DB up.Session

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
		o.Config.AuthorizationTokenTTL = 60
	}

	if o.Config.OauthTokenTTL == (Service{}.Config.OauthTokenTTL) {
		o.Config.OauthTokenTTL = 24
	}

	if o.Config.RefreshTokenTokenTTL == 0 {
		o.Config.RefreshTokenTokenTTL = 24
	}

	if o.Config.PkceImplicitTTL == 0 {
		o.Config.PkceImplicitTTL = 300
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
		fmt.Println(0)
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
		formField := r.Form.Get(field)
		if strings.TrimSpace(formField) == "" {
			if len(formField) > 0 {
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}
	}

	if r.Form.Get("grant_type") != "authorization_code" {
		fmt.Println(3)
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	if r.Form.Get("response_type") != "code" {
		fmt.Println(4)
		return nil, NewErrorResponse(ErrUnsupportedResponseType)
	}

	if r.Form.Get("state") == "" {
		fmt.Println(5)
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	// validate the client
	clientId := r.Form.Get("client_id")
	cid, err := strconv.Atoi(clientId)
	if err != nil {
		fmt.Println(6)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, err := o.GetClient(cid)
	if client == nil {
		fmt.Println(7)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if err != nil {
		fmt.Println(8)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// client type supported by the method
	var supportedClientTypes = []string{
		"authorization_grant",
		"authorization_grant_pkce",
	}

	fmt.Println(client.Type)
	ok := false
	for _, t := range supportedClientTypes {
		if t == client.Type {
			ok = true
			break
		}
	}
	if !ok {
		fmt.Println(85)
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// validate the client redirect uri matches the requested redirect uri
	ok = o.ValidateClientRedirect(r.Form.Get("redirect_uri"), client)
	if !ok {
		fmt.Println(23)
		return nil, NewErrorResponse(ErrInvalidRedirectURI)
	}

	// validate challenge method and code
	_, err = ChallengeCodeValidate(r.Form.Get("code_challenge"), r.Form.Get("code_challenge_method"))
	if err != nil {
		fmt.Println(10)
		return nil, NewErrorResponse(err)
	}

	// Validate the scopes
	ok, _ = scopesValidate(r.Form.Get("scopes"))
	if !ok {
		fmt.Println(231)
		return nil, NewErrorResponse(ErrInvalidScope)
	}

	f := scopesFormat(r.Form.Get("scopes"))

	ok = o.scopesCanBeIssued(f)
	if !ok {
		fmt.Println(76)
		return nil, NewErrorResponse(ErrInvalidScope)
	}

	response := AuthorizationResponse{
		RedirectUri: RedirectUri{
			Path:  r.URL.Path,
			Query: r.URL.RawQuery,
			URI:   fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery),
		},
	}

	return &response, nil
}

// AuthorizationGrantExchangePost processes the authorization form submission.
// Handles authorization_grant, authorization_grant_pkce, and authorization_grant_pkce_implicit flows.
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
		fmt.Println(0)
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	// validate the request for all required fields and confirm values are provided for the field.
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
		//if !params.Has(field) {
		if !r.Form.Has(field) {
			fmt.Println(135)
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	// not empty
	for _, field := range requiredFields {
		//formField := params.Get(field)
		formField := r.Form.Get(field)
		if strings.TrimSpace(formField) == "" {
			if len(formField) > 0 {
				fmt.Println(13)
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}
	}

	//if params.Get("grant_type") == "authorization code" {
	if r.Form.Get("grant_type") == "authorization code" {
		fmt.Println(144)
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// validate the client
	//clientId := params.Get("client_id")
	clientId := r.Form.Get("client_id")
	cid, err := strconv.Atoi(clientId)
	if err != nil {
		fmt.Println(155, clientId)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, err := o.GetClient(cid)
	if client == nil {
		fmt.Println(16)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if err != nil {
		fmt.Println(17)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// client type supported by the method
	var supportedClientTypes = []string{
		"authorization_grant",
		"authorization_grant_pkce",
		"authorization_grant_pkce_implicit",
	}

	ok := false
	for _, t := range supportedClientTypes {
		if t == client.Type {
			ok = true
			break
		}
	}
	if !ok {
		fmt.Println(1881)
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// validate the challenge code and method
	//_, err = ChallengeCodeValidate(params.Get("code_challenge"), params.Get("code_challenge_method"))
	_, err = ChallengeCodeValidate(r.Form.Get("code_challenge"), r.Form.Get("code_challenge_method"))
	if err != nil {
		fmt.Println(19)
		return nil, NewErrorResponse(err)
	}

	switch client.Type {
	case "authorization_grant":
		redirect, err := o.AuthorizationClientExchange(w, r, client)
		if err != nil {
			fmt.Println(187)
			return nil, err
		}

		return redirect, nil
	case "authorization_grant_pkce":
		redirect, err := o.AuthorizationClientCodeExchange(w, r, client)
		if err != nil {
			fmt.Println(176)
			return nil, err
		}

		return redirect, nil
	case "authorization_grant_pkce_implicit":
		auth, err := o.AuthorizationClientCodeExchangeImplicit(w, r, client)
		if err != nil {
			fmt.Println(1987)
			return nil, err
		}

		return auth, nil
	default:
		return nil, NewErrorResponse(ErrInvalidClient)
	}
}

// AccessTokenGrantExchange exchanges credentials for an access token.
// Supports: client_credentials, authorization_grant_pkce, authorization_grant_pkce_implicit,
// and resource_owner_password_credentials grant types.
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
	fmt.Println(4)
	err := r.ParseForm()
	if err != nil {
		fmt.Println(25)
		return nil, NewErrorResponse(ErrInvalidRequest)
	}

	fmt.Println(5)
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
				fmt.Println(127)
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}

		// not empty
		for _, field := range requiredFields {
			formField := r.Form.Get(field)
			if strings.TrimSpace(formField) == "" {
				if len(formField) > 0 {
					fmt.Println(13)
					return nil, NewErrorResponse(ErrInvalidRequest)
				}
			}
		}

		// validate the client
		clientId := r.Form.Get("client_id")
		cid, err := strconv.Atoi(clientId)
		if err != nil {
			fmt.Println(6)
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		client, err := o.GetClient(cid)
		if client == nil {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		if err != nil {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		if client.Revoked != 0 {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// validate client is a supported client for the workflow
		var supportedClientTypes = []string{
			"authorization_grant_pkce",
			"authorization_grant_pkce_implicit",
		}

		ok := false
		for _, t := range supportedClientTypes {
			if t == client.Type {
				ok = true
				break
			}
		}

		if !ok {
			fmt.Println(36)
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// The validation here is a bit different for the code exchange. The code_challenge and code challenge_method are used to verify
		// 1. look up the authorization token by code in the db
		authorizationToken, err := o.GetAuthorizationTokenByToken(r.Form.Get("code"))
		if err != nil {
			fmt.Println(31)
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// 2. Validate client provided code challenge
		ok = o.VerifyAuthorizationCode(*authorizationToken, r.Form.Get("code_verifier"))
		if !ok {
			return nil, NewErrorResponse(ErrInvalidCodeChallenge)
		}

		// 3. does the token challenge code method match the provided code_challenge_method
		if authorizationToken.ChallengeCodeMethod != r.Form.Get("code_challenge_method") {
			fmt.Println(33)
			return nil, NewErrorResponse(ErrInvalidCodeChallenge)
		}

		// 4. was it issued to the client that is making the request?
		if strconv.Itoa(authorizationToken.ClientID) != r.Form.Get("client_id") {
			return nil, NewErrorResponse(ErrInvalidClient)
		}

		// 5. is the authorization token expired?
		ok = o.TokenIsExpired(authorizationToken)
		if !ok {
			fmt.Println(35)
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		// At this point we are good to issue access and refresh tokens for the client. If this request is for a authorization_grant_pkce_implicit client, only generate an access token, otherwise generate both an access and refresh token.

		// access token
		accessToken, err := o.GenerateOauthToken()
		if err != nil {
			fmt.Println(75)
			o.ErrorLog.Println(err)
			return nil, NewErrorResponse(ErrServerError)
		}

		accessToken.ClientID = client.ID

		// validate the scope provided by the client are a string of alpha-numeric characters separated with whitespaces
		ok, _ = scopesValidate(r.Form.Get("scopes"))
		if !ok {
			fmt.Println(764)
			return nil, NewErrorResponse(ErrInvalidScope)
		}

		ok = o.scopesCanBeIssued(scopesFormat(r.Form.Get("scopes")))
		if !ok {
			fmt.Println(765)
			return nil, NewErrorResponse(ErrInvalidScope)
		}

		// We need to check if the scopes can be issued to the client
		if client.Type == "authorization_grant_pkce" {
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

		if client.Type == "authorization_grant_pkce_implicit" {

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
					fmt.Println(77)
					return nil, NewErrorResponse(ErrInvalidScope)
				}
			}

			accessToken.Scopes = strings.Join(f, " ")

			accessToken.Expires = time.Now().UTC().Add(o.Config.PkceImplicitTTL * time.Minute)
		}

		_, err = o.InsertOauthToken(accessToken)

		if err != nil {
			fmt.Println(78)
			o.ErrorLog.Println(err)
			return nil, NewErrorResponse(ErrServerError)
		}

		if client.Type == "authorization_grant_pkce" {
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

			// delete the authorization token from storage
			err = o.DeleteAuthorizationToken(authorizationToken.ID)
			if err != nil {
				o.ErrorLog.Println(err)
			}

			response := OauthResponse{
				GrantType:    "authorization_grant_pkce",
				TokenType:    "Bearer",
				ExpiresIn:    time.Duration(accessToken.Expires.UnixNano()),
				AccessToken:  accessToken.PlainText,
				RefreshToken: refreshToken.PlainText,
			}
			return &response, nil
		}

		// delete the authorization token from storage
		err = o.DeleteAuthorizationToken(authorizationToken.ID)
		if err != nil {
			o.ErrorLog.Println(err)
		}

		response := OauthResponse{
			GrantType:   "authorization_grant_pkce_implicit",
			TokenType:   "Bearer",
			ExpiresIn:   time.Duration(accessToken.Expires.UnixNano()),
			AccessToken: accessToken.PlainText,
		}
		return &response, nil
	}

	// Handle exchange for other grant types
	// check the request for all required fields and confirm values are provided for the field.
	requiredFields := []string{
		"client_id",
		"client_secret",
		"grant_type",
		"scopes",
	}

	if r.Form.Get("grant_type") == "resource_owner_password_credentials" {
		requiredFields = append(requiredFields, "username", "password")
	}

	// required
	for _, field := range requiredFields {
		if !r.Form.Has(field) {
			fmt.Println(120)
			return nil, NewErrorResponse(ErrInvalidRequest)
		}
	}

	// not empty
	for _, field := range requiredFields {
		formField := r.Form.Get(field)
		if strings.TrimSpace(formField) == "" {
			if len(formField) > 0 {
				fmt.Println(13)
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}
	}

	var supportedGrantTypes = []string{
		"client_credentials",
		"resource_owner_password_credentials",
	}
	isSupportedGrant := false
	for _, grantType := range supportedGrantTypes {
		if r.Form.Get("grant_type") == grantType {
			isSupportedGrant = true
			break
		}
	}

	if !isSupportedGrant {
		fmt.Println(123)
		return nil, NewErrorResponse(ErrUnauthorizedClient)
	}

	// validate the client
	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	cid, err := strconv.Atoi(clientId)
	if err != nil {
		fmt.Println(6)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, err := o.GetClient(cid)
	if client == nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if client.Secret != clientSecret {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if client.Revoked != 0 {
		return nil, NewErrorResponse(ErrInvalidClient)
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
			fmt.Println(791)
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
			ExpiresIn:   time.Duration(token.Expires.UnixNano()),
			AccessToken: token.PlainText,
		}
		return &response, nil
	}

	// Resource Owner Password Credentials
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
	if r.Form.Get("grant_type") == "resource_owner_password_credentials" {
		requiredFields := []string{
			"username",
			"password",
		}

		// required
		for _, field := range requiredFields {
			fmt.Println(field)
			if !r.Form.Has(field) {
				fmt.Println(121)
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}

		// not empty
		notEmptyFields := []string{
			"username",
			"password",
		}
		for _, field := range notEmptyFields {
			formField := r.Form.Get(field)
			if strings.TrimSpace(formField) == "" {
				if len(formField) > 0 {
					fmt.Println(13)
					return nil, NewErrorResponse(ErrInvalidRequest)
				}
			}
		}

		token, refreshToken, err := o.ResourceOwnerTokenExchange(r, w, *client)
		if err != nil {
			fmt.Println(543)
			return nil, err
		}

		response := OauthResponse{
			GrantType:    "resource_owner_password_credentials",
			TokenType:    "Bearer",
			ExpiresIn:    time.Duration(token.Expires.UnixNano()),
			AccessToken:  token.PlainText,
			RefreshToken: refreshToken.PlainText,
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
		"client_id",
		"client_secret",
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
		"client_id",
		"client_secret",
		"grant_type",
		"refresh_token",
	}
	for _, field := range notEmptyFields {
		formField := r.Form.Get(field)
		if strings.TrimSpace(formField) == "" {
			if len(formField) > 0 {
				fmt.Println(13)
				return nil, NewErrorResponse(ErrInvalidRequest)
			}
		}
	}

	var supportedClientTypes = []string{
		"authorization_grant",
		"authorization_grant_pkce",
		"client_credentials",
		"refresh_token",
		"resource_owner_password_credentials",
	}

	ok := false
	for _, t := range supportedClientTypes {
		if t == r.Form.Get("grant_type") {
			ok = true
			break
		}
	}
	if !ok {
		fmt.Println(18)
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	if r.Form.Get("grant_type") != "refresh_token" {
		return nil, NewErrorResponse(ErrUnsupportedGrantType)
	}

	// authenticate the client
	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	cid, err := strconv.Atoi(clientId)
	if err != nil {
		fmt.Println(11)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	client, err := o.GetClient(cid)
	if client == nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if err != nil {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if client.Secret != clientSecret {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if client.Revoked != 0 {
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// validate the refresh_token
	rt, err := o.GetRefreshByToken(r.Form.Get("refresh_token"))
	if err != nil || rt == nil {
		fmt.Println(14)
		return nil, NewErrorResponse(ErrInvalidRefreshToken)
	}

	// ensure that the refresh token was issued to the authenticated client
	at, err := o.GetOauthToken(rt.AccessTokenID)
	if err != nil || at == nil {
		fmt.Println(15)
		return nil, NewErrorResponse(ErrInvalidRefreshToken)
	}

	requestClientID, err := strconv.Atoi(r.Form.Get("client_id"))
	if err != nil {
		o.ErrorLog.Println(16)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	if at.ClientID != requestClientID {
		fmt.Println(17)
		return nil, NewErrorResponse(ErrInvalidClient)
	}

	// Is the refresh token expired?
	ok = o.TokenIsExpired(rt)
	if !ok {
		fmt.Println(935)
		return nil, NewErrorResponse(ErrExpiredRefreshToken)
	}

	// validate the scopes provided are formatted properly
	ok, _ = scopesValidate(r.Form.Get("scopes"))
	if !ok {
		fmt.Println(194)
		return nil, NewErrorResponse(ErrInvalidScope)
	}

	// RFC 6749 defines a request to refresh may not contain a scope that is not already assigned to the access token
	scopesMap := scopesFormat(r.Form.Get("scopes"))
	if scopesMap != nil {
		existingScopes := strings.Split(at.Scopes, " ")
		for _, scope := range scopesMap {
			if !slices.Contains(existingScopes, scope) {
				fmt.Println(187)
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
		GrantType:    "authorization_grant_pkce_implicit",
		TokenType:    "Bearer",
		ExpiresIn:    time.Duration(accessToken.Expires.UnixNano()),
		AccessToken:  accessToken.PlainText,
		RefreshToken: refreshToken.PlainText,
	}
	return &response, nil

}
