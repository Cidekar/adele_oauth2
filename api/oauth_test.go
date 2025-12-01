package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cidekar/adele-framework"
	"golang.org/x/crypto/bcrypt"
)

func TestOauth_Oauth_New(t *testing.T) {
	o := New(&ade)

	if reflect.TypeOf(o).String() != "api.Service" {
		t.Error("oauth new did not return a new Service object")
	}

}

func TestOauth_Oauth_Authorization_Grant_Exchange(t *testing.T) {

	setupOauthMTest(ade)
	defer tearDownOauthMTest(ade)

	config := Configuration{
		GuardedRouteGroups: []string{
			"/api",
		},
		AuthorizationTokenTTL: 60,
		OauthTokenTTL:         24 * time.Hour,
		RefreshTokenTokenTTL:  24 * time.Hour,
		Scopes: map[string]string{
			"ping": "Allows access to the ping resource",
			"pong": "Allows access to the pong resource",
		},
	}

	o := NewWithConfig(&ade, config)

	qp := url.Values{}

	url := o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req := httptest.NewRequest("GET", url, nil)
	_, errRes := o.AuthorizationGrantExchange(httptest.NewRecorder(), req)
	if errRes.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Errorf("authorization grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, StatusCodes[ErrInvalidRequest])
	}

	if reflect.TypeOf(o).String() != "api.Service" {
		t.Error("oauth new did not return a new Service object")

	}

	qp.Set("client_id", "1")
	qp.Set("grant_type", "authorization_code")
	qp.Set("response_type", "code")
	qp.Set("redirect_uri", "https://localhost/callback")
	qp.Set("state", "12345")
	qp.Set("code_challenge", "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU")
	qp.Set("code_challenge_method", "S256")
	qp.Set("scopes", "ping pong")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)
	at, errRes := o.AuthorizationGrantExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("authorization grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.AuthorizationResponse" {
		t.Error("authorization grant exchange returned unexpected type")
	}
}

func TestOauth_Oauth_Authorization_Grant_Exchange_Post(t *testing.T) {

	setupOauthMTest(ade)
	defer tearDownOauthMTest(ade)

	config := Configuration{
		GuardedRouteGroups: []string{
			"/api",
		},
		AuthorizationTokenTTL: 60,
		OauthTokenTTL:         24 * time.Hour,
		RefreshTokenTokenTTL:  24 * time.Hour,
		Scopes: map[string]string{
			"ping": "Allows access to the ping resource",
			"pong": "Allows access to the pong resource",
		},
	}

	o := NewWithConfig(&ade, config)

	qp := url.Values{}

	url := o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req := httptest.NewRequest("GET", url, nil)
	_, errRes := o.AuthorizationGrantExchangePost(httptest.NewRecorder(), req)
	if errRes.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Errorf("authorization grant exchange post returned %d error when it should have returned %d", errRes.ErrorCode, StatusCodes[ErrInvalidRequest])
	}

	if reflect.TypeOf(o).String() != "api.Service" {
		t.Error("oauth new did not return a new Service object")

	}

	qp.Set("client_id", "1")
	qp.Set("grant_type", "authorization_code")
	qp.Set("response_type", "code")
	qp.Set("redirect_uri", "https://localhost/callback")
	qp.Set("state", "12345")
	qp.Set("code_challenge", "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU")
	qp.Set("code_challenge_method", "S256")
	qp.Set("scopes", "ping pong")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)
	at, errRes := o.AuthorizationGrantExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("authorization grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.AuthorizationResponse" {
		t.Error("authorization grant exchange returned unexpected type")
	}

	// new up for testing
	o = NewWithConfig(&ade, Configuration{
		GuardedRouteGroups: []string{
			"/api",
		},
		UnguardedRoutes: []string{
			"/api/health",
			"/api/oauth/token",
			"/api/oauth/token/refresh",
			"/api/oauth/authorize",
		},
		AuthorizationTokenTTL: 60,
		OauthTokenTTL:         24 * time.Hour,
		RefreshTokenTokenTTL:  24 * time.Hour,
		PkceImplicitAuthorizationScopes: map[string]string{
			"ping": "Allows access to the ping resource",
		},
		Scopes: map[string]string{
			"ping": "Allows access to the ping resource",
			"pong": "Allows access to the pong resource",
		},
	})

	// authorization_grant
	qp.Set("client_id", "3")
	qp.Set("grant_type", "authorization_code")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err := o.Session.Load(req.Context(), req.Header.Get("X-Session"))
	if err != nil {
		panic(err)
	}

	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	at, errRes = o.AuthorizationGrantExchangePost(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("authorization grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.AuthorizationResponse" {
		t.Error("authorization grant exchange returned unexpected type")
	}

	if at.GrantType != "authorization_grant_verify" {
		t.Errorf("authorization grant exchange returned %s, but expectedauthorization_grant_verify", at.GrantType)
	}

	// authorization_grant_pkce
	qp.Set("client_id", "1")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), req.Header.Get("X-Session"))
	if err != nil {
		panic(err)
	}

	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	at, errRes = o.AuthorizationGrantExchangePost(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("authorization grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.AuthorizationResponse" {
		t.Error("authorization grant exchange returned unexpected type")
	}

	// authorization_grant_pkce_implicit
	qp.Set("client_id", "2")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), req.Header.Get("X-Session"))
	if err != nil {
		panic(err)
	}

	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	at, errRes = o.AuthorizationGrantExchangePost(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("authorization grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.AuthorizationResponse" {
		t.Error("authorization grant exchange returned unexpected type")
	}

}

func TestOauth_Oauth_Access_Token_Grant_Exchange(t *testing.T) {

	setupOauthMTest(ade)
	defer tearDownOauthMTest(ade)

	config := Configuration{
		GuardedRouteGroups: []string{
			"/api",
		},
		AuthorizationTokenTTL: 60,
		OauthTokenTTL:         24 * time.Hour,
		RefreshTokenTokenTTL:  24 * time.Hour,
		Scopes: map[string]string{
			"ping": "Allows access to the ping resource",
			"pong": "Allows access to the pong resource",
		},
		PkceImplicitAuthorizationScopes: map[string]string{
			"ping": "Allows access to the machine resources",
			"pong": "Allows access to the pong resource",
		},
	}

	o := NewWithConfig(&ade, config)

	qp := url.Values{}

	url := o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req := httptest.NewRequest("GET", url, nil)
	_, errRes := o.AccessTokenGrantExchange(httptest.NewRecorder(), req)
	if errRes.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Errorf("authorization grant exchange post returned %d error when it should have returned %d", errRes.ErrorCode, StatusCodes[ErrInvalidRequest])
	}

	if reflect.TypeOf(o).String() != "api.Service" {
		t.Error("oauth new did not return a new Service object")

	}

	user := User{
		ID: 1,
	}

	// Authorization Grant PKCE
	// Authorization token create and insert for testing the request
	at, _ := o.GenerateAuthorizationToken()
	at.ClientID = 1
	at.UserID = &user.ID
	at.Expires = time.Now().UTC().Add(24 * time.Hour)
	at.ChallengeCode = "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU"
	at.ChallengeCodeMethod = "S256"
	at, _ = o.InsertAuthorizationToken(at)

	// Setup the request parameters
	qp.Set("client_id", "1")
	qp.Set("grant_type", "authorization_code")
	qp.Set("code", at.PlainText)
	qp.Set("code_verifier", "xuDagaErmffpBPRyKGvpf0MVYeAynexTODe69MvFsxI8ftz")
	qp.Set("code_challenge_method", "S256")
	qp.Set("scopes", "ping pong")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()

	req = httptest.NewRequest("GET", url, nil)

	// Make a request
	res, errRes := o.AccessTokenGrantExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("access token grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(res).String() != "*api.OauthResponse" {
		t.Error("access token grant exchange returned unexpected type")
	}

	if res.AccessToken == "" {
		t.Error("access token grant exchange returned empty access token and it should not")
	}

	if res.RefreshToken == "" {
		t.Error("access token grant exchange returned empty refresh token and it should not")
	}

	// Authorization Grant PKCE Implicit
	// Authorization token create and insert for testing the request
	at, _ = o.GenerateAuthorizationToken()
	at.ClientID = 2
	at.UserID = &user.ID
	at.Expires = time.Now().UTC().Add(24 * time.Hour)
	at.ChallengeCode = "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU"
	at.ChallengeCodeMethod = "S256"
	at, _ = o.InsertAuthorizationToken(at)

	// Setup the request parameters
	qp.Set("client_id", "2")
	qp.Set("grant_type", "authorization_code")
	qp.Set("code", at.PlainText)
	qp.Set("code_verifier", "xuDagaErmffpBPRyKGvpf0MVYeAynexTODe69MvFsxI8ftz")
	qp.Set("code_challenge_method", "S256")
	qp.Set("scopes", "ping pong")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	// Make a request
	res, errRes = o.AccessTokenGrantExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("access token grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(res).String() != "*api.OauthResponse" {
		t.Error("access token grant exchange returned unexpected type")
	}

	if res.AccessToken == "" {
		t.Error("access token grant exchange returned empty access token and it should not")
	}

	if res.RefreshToken != "" {
		t.Error("access token grant exchange returned a refresh token and it should not")
	}

	// Resource Owner Password Credentials Grant
	// Create a client
	secret := generateClientSecret()
	collection := upper.Collection("oauth_clients")
	_, err := collection.Insert(Client{
		Secret: secret,
		Name:   "Adele",
		Type:   "resource_owner_password_credentials",
		UserID: &user.ID,
	})
	if err != nil {
		panic(err)
	}

	// Remove request parameters
	qp.Del("code")
	qp.Del("code_verifier")
	qp.Del("code_challenge_method")

	// Setup the request parameters
	qp.Set("client_id", "4")
	qp.Set("client_secret", secret)
	qp.Set("grant_type", "resource_owner_password_credentials")
	qp.Set("scopes", "ping pong")
	qp.Set("username", "adele@localhost.net")
	qp.Set("password", "Password")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	// Make a request
	res, errRes = o.AccessTokenGrantExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("access token grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(res).String() != "*api.OauthResponse" {
		t.Error("access token grant exchange returned unexpected type")
	}

	if res.AccessToken == "" {
		t.Error("access token grant exchange returned empty access token and it should not")
	}

	if res.RefreshToken == "" {
		t.Error("access token grant exchange returned a refresh token and it should not")
	}

	// Client Credentials
	// Create a client
	secret = generateClientSecret()
	collection = upper.Collection("oauth_clients")
	_, err = collection.Insert(Client{
		Secret: secret,
		Name:   "Adele",
		Type:   "client_credentials",
		UserID: &user.ID,
	})
	if err != nil {
		panic(err)
	}

	// Remove request parameters
	qp.Del("username")
	qp.Del("password")

	// Setup the request parameters
	qp.Set("client_id", "5")
	qp.Set("client_secret", secret)
	qp.Set("grant_type", "client_credentials")
	qp.Set("scopes", "ping pong")

	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	// Make a request
	res, errRes = o.AccessTokenGrantExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("access token grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(res).String() != "*api.OauthResponse" {
		t.Error("access token grant exchange returned unexpected type")
	}

	if res.AccessToken == "" {
		t.Error("access token grant exchange returned empty access token and it should not")
	}

	if res.RefreshToken != "" {
		t.Error("access token grant exchange returned a refresh token and it should not")
	}

}

func TestOauth_Oauth_Refresh_Token_Exchange(t *testing.T) {

	setupOauthMTest(ade)
	defer tearDownOauthMTest(ade)

	config := Configuration{
		GuardedRouteGroups: []string{
			"/api",
		},
		AuthorizationTokenTTL: 60,
		OauthTokenTTL:         24 * time.Hour,
		RefreshTokenTokenTTL:  24 * time.Hour,
		Scopes: map[string]string{
			"ping": "Allows access to the ping resource",
			"pong": "Allows access to the pong resource",
		},
	}

	o := NewWithConfig(&ade, config)

	qp := url.Values{}

	url := o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req := httptest.NewRequest("GET", url, nil)
	_, errRes := o.RefreshTokenExchange(httptest.NewRecorder(), req)
	if errRes.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Errorf("refresh token exchange returned %d error when it should have returned %d", errRes.ErrorCode, StatusCodes[ErrInvalidRequest])
	}

	if reflect.TypeOf(o).String() != "api.Service" {
		t.Error("oauth new did not return a new Service object")

	}

	user := User{
		ID: 1,
	}

	// Create a client
	secret := generateClientSecret()
	collection := upper.Collection("oauth_clients")
	_, err := collection.Insert(Client{
		Secret: secret,
		Name:   "Adele",
		Type:   "authorization_grant",
		UserID: &user.ID,
	})
	if err != nil {
		panic(err)
	}

	// Create access token
	ot, err := o.GenerateOauthToken()
	if err != nil {
		t.Error("generate oauth token returned an error when it should not")
	}

	if ot == &(OauthToken{}) {
		t.Error("generate oauth token returned an empty struct when it should not")
	}

	ot.ClientID = 4
	ot.UserID = &user.ID
	ot.Expires = time.Now().UTC().Add(24 * time.Hour)
	ot.Scopes = "ping pong"
	ot, err = o.InsertOauthToken(ot)
	if err != nil {
		t.Error("insert oauth token returned an error when it should not")
	}

	// Create a refresh token
	rt, err := o.GenerateRefreshToken(user.ID, ot.ID, 5)
	if err != nil {
		t.Error("insert oauth token returned an error when it should not")
	}
	rt.Expires = time.Now().UTC().Add(24 * time.Hour)

	err = o.InsertRefreshToken(rt)
	if err != nil {
		t.Error("insert refresh token returned an error when it should not")
	}

	// Setup the request parameters
	qp.Add("client_id", "4")
	qp.Add("client_secret", secret)
	qp.Add("grant_type", "refresh_token")
	qp.Add("scopes", "ping pong")
	qp.Add("refresh_token", rt.PlainText)
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	// Make a request
	res, errRes := o.RefreshTokenExchange(httptest.NewRecorder(), req)
	if errRes != nil {
		t.Errorf("access token grant exchange returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(res).String() != "*api.OauthResponse" {
		t.Error("access token grant exchange returned unexpected type")
	}

	if res.AccessToken == "" {
		t.Error("access token grant exchange returned empty access token and it should not")
	}

	if res.RefreshToken == "" {
		t.Error("access token grant exchange returned a refresh token and it should not")
	}

}

func setupOauthMTest(_ adele.Adele) {
	// Run migrations via raw SQL
	upBytes, err := templateFS.ReadFile("testmigrations/oauth_test_postgres.sql")
	if err != nil {
		panic(err)
	}

	_, err = upper.SQL().Exec(string(upBytes))
	if err != nil {
		panic(err)
	}

	// Seed user
	passHash, err := bcrypt.GenerateFromPassword([]byte("Password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	collection := upper.Collection("users")
	collection.Insert(User{
		Email:     "adele@localhost.net",
		FirstName: "Adele",
		LastName:  "Wiring Code",
		Password:  string(passHash),
	})

	// Seed client
	collection = upper.Collection("oauth_clients")
	_, err = collection.Insert(Client{
		Secret:      generateClientSecret(),
		Name:        "Adele",
		Type:        "authorization_grant_pkce",
		RedirectUrl: "https://localhost/callback",
	})
	if err != nil {
		panic(err)
	}

	_, err = collection.Insert(Client{
		Secret:      generateClientSecret(),
		Name:        "Adele",
		Type:        "authorization_grant_pkce_implicit",
		RedirectUrl: "https://localhost/callback",
	})
	if err != nil {
		panic(err)
	}

	collection = upper.Collection("oauth_clients")
	_, err = collection.Insert(Client{
		Secret:      generateClientSecret(),
		Name:        "Adele",
		Type:        "authorization_grant",
		RedirectUrl: "https://localhost/callback",
	})
	if err != nil {
		panic(err)
	}
}

func tearDownOauthMTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users, oauth_clients, tokens, refresh_tokens, authorization_tokens CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}
