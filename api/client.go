package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/CloudyKit/jet/v6"
	up "github.com/upper/db/v4"
	"golang.org/x/crypto/bcrypt"
)

// Get the client by the ID and if no client is found the return value will be nil.
func (o *Service) GetClient(id int) (*Client, error) {
	var client Client

	collection := DB.Collection("oauth_clients")
	res := collection.Find(up.Cond{"id =": id})

	err := res.One(&client)
	if err != nil {
		if err == up.ErrNoMoreRows {
			return nil, nil
		}
		return nil, err
	}

	return &client, nil
}

// Validate that a given uri can be used for redirection.
func (o *Service) ValidateClientRedirect(uri string, client *Client) bool {
	if uri == "" {
		return false
	}

	decoded, err := url.PathUnescape(uri)
	if err != nil {
		return false
	}

	if client.RedirectUrl == decoded {
		return true
	}

	return false
}

func (o *Service) AuthorizationClientExchange(w http.ResponseWriter, r *http.Request, client *Client) (*AuthorizationResponse, *ErrorResponse) {

	err := r.ParseForm()
	if err != nil {
		fmt.Println(22)
		return nil, NewErrorResponse(ErrServerError)
	}

	// If the user is not logged into the application, log them in using their credentials provided by the HTTP request.
	if !o.UserIsLoggedIn(r) {

		requiredFields := []string{
			"username",
			"password",
		}

		// required
		for _, field := range requiredFields {
			exist := r.Form.Get(field)
			if exist == "" {
				fmt.Println(12)
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

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// Check the username and password are correct
		var user User
		collection := DB.Collection("users")
		res := collection.Find(up.Cond{"email =": username})
		err := res.One(&user)

		if err != nil {

			if err == up.ErrNoMoreRows {
				return nil, NewErrorResponse(ErrInvalidGrant)
			}
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		if reflect.DeepEqual(user, User{}) {
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			switch {
			case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
				return nil, NewErrorResponse(ErrInvalidGrant)
			default:
				return nil, NewErrorResponse(ErrInvalidGrant)
			}
		}

	}

	// A authenticated application user is trying to grant access to the client to create a authorization code on their behalf.
	if r.Form.Get("allow_access") == "permission given" {
		user := o.GetAuthenticatedUser(r)
		token, err := o.GenerateAuthorizationToken()
		if err != nil {
			fmt.Println(23)
			return nil, NewErrorResponse(ErrServerError)
		}
		token.State = r.Form.Get("state")
		token.UserID = &user.ID
		token.ClientID = client.ID
		statefulToken, err := o.InsertAuthorizationToken(token)
		if err != nil {
			fmt.Println(24)
			return nil, NewErrorResponse(ErrServerError)
		}

		redirect := AuthorizationResponse{
			GrantType: "authorization_grant_pkce",
			RedirectUri: RedirectUri{
				Path:  client.RedirectUrl,
				Query: fmt.Sprintf("code=%s&state=%s", statefulToken.PlainText, r.Form.Get("state")),
				URI:   fmt.Sprintf("%s?code=%s&state=%s", client.RedirectUrl, statefulToken.PlainText, r.Form.Get("state")),
			},
		}

		return &redirect, nil
	}

	var scopes []string
	if r.Form.Get("scopes") != "" {
		scopes = strings.Split(r.Form.Get("scopes"), " ")
		for i, s := range scopes {
			scopes[i] = strings.TrimSpace(s)
		}
	}

	vars := make(jet.VarMap)
	vars.Set("client", client.Name)
	vars.Set("scopes", scopes)
	vars.Set("url", fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery))

	o.Renderer.Page(w, r, o.Config.VerifyTemplatePath, vars, nil)

	return &AuthorizationResponse{
		GrantType: "authorization_grant_verify",
	}, nil

}

func (o *Service) AuthorizationClientCodeExchange(w http.ResponseWriter, r *http.Request, client *Client) (*AuthorizationResponse, *ErrorResponse) {

	err := r.ParseForm()
	if err != nil {
		fmt.Println(22)
		return nil, NewErrorResponse(ErrServerError)
	}

	// If the user is not logged into the application, log them in using their credentials provided by the HTTP request.
	if !o.UserIsLoggedIn(r) {

		requiredFields := []string{
			"username",
			"password",
		}

		// required
		for _, field := range requiredFields {
			exist := r.Form.Get(field)
			if exist == "" {
				fmt.Println(12)
				return nil, NewErrorResponse(ErrAccessDenied)
			}
		}

		// not empty
		for _, field := range requiredFields {
			formField := r.Form.Get(field)
			if strings.TrimSpace(formField) == "" {
				if len(formField) > 0 {
					fmt.Println(13)
					return nil, NewErrorResponse(ErrAccessDenied)
				}
			}
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// Check the username and password are correct
		var user User
		collection := DB.Collection("users")
		res := collection.Find(up.Cond{"email =": username})
		err := res.One(&user)

		if err != nil {

			if err == up.ErrNoMoreRows {
				return nil, NewErrorResponse(ErrInvalidGrant)
			}
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		if reflect.DeepEqual(user, User{}) {
			return nil, NewErrorResponse(ErrInvalidGrant)
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			switch {
			case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
				return nil, NewErrorResponse(ErrInvalidGrant)
			default:
				return nil, NewErrorResponse(ErrInvalidGrant)
			}
		}
	}

	// A authenticated application user is trying to grant access to the client to create a authorization code on their behalf.
	if r.Form.Get("allow_access") == "permission given" {
		user := o.GetAuthenticatedUser(r)
		token, err := o.GenerateAuthorizationToken()
		if err != nil {
			fmt.Println(23)
			return nil, NewErrorResponse(ErrServerError)
		}

		token.ChallengeCode = r.Form.Get("code_challenge")
		token.ChallengeCodeMethod = r.Form.Get("code_challenge_method")
		token.State = r.Form.Get("state")
		token.UserID = &user.ID
		token.ClientID = client.ID
		statefulToken, err := o.InsertAuthorizationToken(token)
		if err != nil {
			fmt.Println(24)
			return nil, NewErrorResponse(ErrServerError)
		}

		redirect := AuthorizationResponse{
			GrantType: "authorization_grant_pkce",
			RedirectUri: RedirectUri{
				Path:  client.RedirectUrl,
				Query: fmt.Sprintf("code=%s&state=%s", statefulToken.PlainText, r.Form.Get("state")),
				URI:   fmt.Sprintf("%s?code=%s&state=%s", client.RedirectUrl, statefulToken.PlainText, r.Form.Get("state")),
			},
		}

		return &redirect, nil
	}

	var scopes []string
	if r.Form.Get("scopes") != "" {
		scopes = strings.Split(r.Form.Get("scopes"), " ")
		for i, s := range scopes {
			scopes[i] = strings.TrimSpace(s)
		}
	}

	vars := make(jet.VarMap)
	vars.Set("client", client.Name)
	vars.Set("scopes", scopes)
	vars.Set("url", fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery))

	o.Renderer.Page(w, r, o.Config.VerifyTemplatePath, vars, nil)

	return &AuthorizationResponse{
		GrantType: "authorization_grant_verify",
	}, nil
}

func (o *Service) AuthorizationClientCodeExchangeImplicit(w http.ResponseWriter, r *http.Request, client *Client) (*AuthorizationResponse, *ErrorResponse) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(40)
		return nil, NewErrorResponse(ErrServerError)
	}

	token, err := o.GenerateAuthorizationToken()
	if err != nil {
		fmt.Println(41)
		return nil, NewErrorResponse(ErrServerError)
	}

	token.ChallengeCode = r.Form.Get("code_challenge")
	token.ChallengeCodeMethod = r.Form.Get("code_challenge_method")
	token.State = r.Form.Get("state")
	token.ClientID = client.ID
	statefulToken, err := o.InsertAuthorizationToken(token)
	if err != nil {
		fmt.Println(42)
		return nil, NewErrorResponse(ErrServerError)
	}

	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fmt.Println(43)
		return nil, NewErrorResponse(ErrServerError)
	}

	res := &AuthorizationResponse{
		GrantType: "authorization_grant_pkce_implicit",
		TokenType: "code",
		Code:      statefulToken.PlainText,
		State:     params.Get("state"),
	}

	return res, nil
}

func (o *Service) ResourceOwnerTokenExchange(r *http.Request, w http.ResponseWriter, client Client) (*OauthToken, *RefreshToken, *ErrorResponse) {

	err := r.ParseForm()
	if err != nil {
		fmt.Println(22)
		return nil, nil, NewErrorResponse(ErrServerError)
	}

	// user validation
	requiredFields := []string{
		"username",
		"password",
	}
	// required
	for _, field := range requiredFields {
		if !r.Form.Has(field) {
			fmt.Println(121)
			return nil, nil, NewErrorResponse(ErrInvalidRequest)
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
				return nil, nil, NewErrorResponse(ErrInvalidRequest)
			}
		}
	}

	user, err := o.GetUserByEmail(r.Form.Get("username"))
	if err != nil || user == nil {
		return nil, nil, NewErrorResponse(ErrAccessDenied)
	}

	matches := o.CheckUserPasswordMatches(r.Form.Get("password"), *user)
	if !matches {
		return nil, nil, NewErrorResponse(ErrAccessDenied)
	}

	// access token
	token, err := o.GenerateOauthToken()
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, nil, NewErrorResponse(ErrServerError)
	}

	token.ClientID = client.ID
	token.UserID = &user.ID

	ok, _ := scopesValidate(r.Form.Get("scopes"))
	if !ok {
		return nil, nil, NewErrorResponse(ErrInvalidScope)
	}

	f := scopesFormat(r.Form.Get("scopes"))

	ok = o.scopesCanBeIssued(f)
	if !ok {
		fmt.Println(76)
		return nil, nil, NewErrorResponse(ErrInvalidScope)
	}

	token.Scopes = strings.Join(f, " ")

	_, err = o.InsertOauthToken(token)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, nil, NewErrorResponse(ErrServerError)
	}

	// Generate a refresh token that can be used when the current access token becomes invalid or expires.
	refreshToken, err := o.GenerateRefreshToken(user.ID, token.ID, client.ID)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, nil, NewErrorResponse(ErrServerError)
	}

	// Persist the refresh token
	err = o.InsertRefreshToken(refreshToken)
	if err != nil {
		o.ErrorLog.Println(err)
		return nil, nil, NewErrorResponse(ErrServerError)
	}

	return token, refreshToken, nil
}
