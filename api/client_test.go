package api

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/cidekar/adele-framework"
	"golang.org/x/crypto/bcrypt"
)

func TestOauth_Client(t *testing.T) {
	setupClientTest(ade)
	defer tearDownClientTest(ade)

	var config = Configuration{
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
	}

	o := NewWithConfig(&ade, config)

	c, err := o.GetClient(1)
	if err != nil {
		t.Error("error was returned when trying to get a client")
	}

	if c == nil {
		t.Error("client was not found when one should have been found")
	}

	c, err = o.GetClient(3)
	if err != nil {
		t.Error("error was returned when trying to get a client")
	}
	ok := o.ValidateClientRedirect("https://localhost/callback", c)
	if !ok {
		t.Error("client redirect uri was not valid when it should be")
	}

	// AuthorizationClientExchange
	// unauthenticated and wrong credentials return invalid grant
	qp := url.Values{}
	qp.Add("username", "wrong@localhost.net")
	qp.Add("password", "WrongPassword")

	url := o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req := httptest.NewRequest("GET", url, nil)

	ctx, err := o.Session.Load(req.Context(), req.Header.Get("X-Session"))
	if err != nil {
		panic(err)
	}
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	_, errRes := o.AuthorizationClientExchange(w, req, &ClientCredentialsGrant)
	if errRes == nil {
		t.Fatal("authorization client exchange returned no error when it should")
	}

	if errRes.ErrorCode != StatusCodes[ErrInvalidGrant] {
		t.Errorf("authorization client exchange returned %d when it should be %d", errRes.ErrorCode, StatusCodes[ErrInvalidGrant])
	}

	// unauthenticated users can login using their credentials provided by the HTTP request
	qp.Add("username", "adele@localhost.net")
	qp.Add("password", "Password")

	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), "1234")
	if err != nil {
		panic(err)
	}
	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	ar, errRes := o.AuthorizationClientExchange(w, req, &ClientCredentialsGrant)
	if errRes != nil {
		t.Error("authorization client exchange returned error when it should not")
	}

	if ar.GrantType != "authorization_grant_verify" {
		t.Errorf("authorization client exchange returned %s when it should be authorization_grant_verify", ar.GrantType)
	}

	// authenticated users get redirect after permission
	client, _ := o.GetClient(3)
	qp.Add("username", "adele@localhost.net")
	qp.Add("password", "Password")
	qp.Add("allow_access", "permission given")
	qp.Add("state", "123456789")

	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), "1234")
	if err != nil {
		panic(err)
	}
	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	ar, errRes = o.AuthorizationClientExchange(w, req, client)
	if errRes != nil {
		t.Error("authorization client exchange returned error when it should not")
	}

	if ar.GrantType != "authorization_grant_pkce" {
		t.Errorf("authorization client exchange returned %s when it should be authorization_grant_verify", ar.GrantType)
	}

	if ar.RedirectUri.Path != "https://localhost/callback" {
		t.Error("authorization client exchange returned an unexpected path")
	}
	if ar.RedirectUri.Query == "" {
		t.Error("authorization client exchange returned an unexpected query")
	}
	if ar.RedirectUri.URI == "" {
		t.Error("authorization client exchange returned an unexpected uri")
	}

	// AuthorizationClientCodeExchange
	// unauthenticated and wrong credentials return invalid grant
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), req.Header.Get("X-Session"))
	if err != nil {
		panic(err)
	}
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	_, errRes = o.AuthorizationClientCodeExchange(w, req, &ClientCredentialsGrant)
	if errRes == nil {
		t.Error("authorization client code exchange returned no error when it should")
	}

	if errRes != nil && errRes.ErrorCode != StatusCodes[ErrInvalidGrant] {
		t.Errorf("authorization client code exchange returned %d error when it should have returned %d", errRes.ErrorCode, StatusCodes[ErrInvalidGrant])
	}

	// unauthenticated users can login using their credentials provided by the HTTP request
	qp.Add("username", "adele@localhost.net")
	qp.Add("password", "Password")

	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), "1234")
	if err != nil {
		panic(err)
	}
	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	ar, errRes = o.AuthorizationClientCodeExchange(w, req, &ClientCredentialsGrant)
	if errRes != nil {
		t.Error("authorization client exchange returned error when it should not")
	}

	if ar.GrantType != "authorization_grant_pkce" {
		t.Errorf("authorization client exchange returned %s when it should be authorization_grant_pkce", ar.GrantType)
	}

	// authenticated users get redirect after permission
	client, _ = o.GetClient(3)
	qp.Add("username", "adele@localhost.net")
	qp.Add("password", "Password")
	qp.Add("allow_access", "permission given")
	qp.Add("state", "123456789")
	qp.Add("code_challenge", "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU")
	qp.Add("code_challenge_method", "S256")

	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)

	ctx, err = o.Session.Load(req.Context(), "1234")
	if err != nil {
		panic(err)
	}
	o.Session.Put(ctx, "userID", "1")
	o.Session.Load(ctx, "1234")

	req = req.WithContext(ctx)

	w = httptest.NewRecorder()
	ar, errRes = o.AuthorizationClientCodeExchange(w, req, client)
	if errRes != nil {
		t.Error("authorization client exchange returned error when it should not")
	}

	if ar.GrantType != "authorization_grant_pkce" {
		t.Errorf("authorization client exchange returned %s when it should be authorization_grant_verify", ar.GrantType)
	}

	if ar.RedirectUri.Path != "https://localhost/callback" {
		t.Error("authorization client exchange returned an unexpected path")
	}
	if ar.RedirectUri.Query == "" {
		t.Error("authorization client exchange returned an unexpected query")
	}
	if ar.RedirectUri.URI == "" {
		t.Error("authorization client exchange returned an unexpected uri")
	}

	// AuthorizationClientCodeExchangeImplicit
	client, _ = o.GetClient(3)
	qp.Add("state", "123456789")
	qp.Add("code_challenge", "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU")
	qp.Add("code_challenge_method", "S256")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	ar, errRes = o.AuthorizationClientCodeExchangeImplicit(w, req, client)
	if errRes != nil {
		t.Error("authorization client code exchange returned error when it should not")
	}

	if ar.GrantType != "authorization_grant_pkce_implicit" {
		t.Errorf("authorization client code exchange returned %s when it should be authorization_grant_verify", ar.GrantType)
	}

	if ar.TokenType != "code" {
		t.Error("authorization client code exchange returned an unexpected type")
	}

	if ar.State != "123456789" {
		t.Error("authorization client code exchange returned an unexpected state")
	}

	authToken, _ := o.GetAuthorizationTokenByToken(ar.Code)
	if ar.Code != authToken.PlainText {
		t.Error("authorization client code exchange returned an unexpected code")
	}

}

func TestOauth_Client_Resource_Owner_Password_Credentials(t *testing.T) {
	setupClientTest(ade)
	defer tearDownClientTest(ade)

	var config = Configuration{
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

	// unauthenticated and no credentials
	client, _ := o.GetClient(2)
	url := o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req := httptest.NewRequest("GET", url, nil)
	_, _, errRes := o.ResourceOwnerTokenExchange(req, httptest.NewRecorder(), *client)
	if errRes.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Errorf("resource owner password credentials returned %d error when it should have returned %d", errRes.ErrorCode, StatusCodes[ErrInvalidRequest])
	}

	// unauthenticated can authenticate and get access and refresh tokens
	qp.Set("username", "adele@localhost.net")
	qp.Set("password", "Password")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)
	at, rt, errRes := o.ResourceOwnerTokenExchange(req, httptest.NewRecorder(), *client)
	if errRes != nil {
		t.Errorf("resource owner password credentials returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.OauthToken" {
		t.Errorf("resource owner password credentials returned wrong type")
	}

	if reflect.TypeOf(rt).String() != "*api.RefreshToken" {
		t.Errorf("resource owner password credentials returned wrong type")
	}

	// unauthenticated can authenticate and get access and refresh tokens with scopes
	qp.Set("username", "adele@localhost.net")
	qp.Set("password", "Password")
	qp.Set("scopes", "ping pong")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)
	at, rt, errRes = o.ResourceOwnerTokenExchange(req, httptest.NewRecorder(), *client)
	if errRes != nil {
		t.Errorf("resource owner password credentials returned %d error when it should have returned %d", errRes.ErrorCode, http.StatusOK)
	}

	if reflect.TypeOf(at).String() != "*api.OauthToken" {
		t.Errorf("resource owner password credentials returned wrong type")
	}

	if reflect.TypeOf(rt).String() != "*api.RefreshToken" {
		t.Errorf("resource owner password credentials returned wrong type")
	}

	// unauthenticated can authenticate and get access and refresh tokens with scopes causes error
	qp.Set("username", "adele@localhost.net")
	qp.Set("password", "Password")
	qp.Set("scopes", "ping pong oops")
	url = o.Config.GuardedRouteGroups[0] + "?" + qp.Encode()
	req = httptest.NewRequest("GET", url, nil)
	_, _, errRes = o.ResourceOwnerTokenExchange(req, httptest.NewRecorder(), *client)
	if errRes == nil {
		t.Errorf("resource owner password credentials did not return an error when it should have returned one")
	}
}

func setupClientTest(_ adele.Adele) {
	// Run migrations via raw SQL
	upBytes, err := templateFS.ReadFile("testmigrations/oauth_test_postgres.sql")
	if err != nil {
		panic(err)
	}

	_, err = upper.SQL().Exec(string(upBytes))
	if err != nil {
		panic(err)
	}

	// Seed user with bcrypt password
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
	ClientCredentialsGrant = Client{
		Secret: generateClientSecret(),
		Name:   "Adele",
		Type:   "client_credentials",
	}
	collection = upper.Collection("oauth_clients")
	res, err := collection.Insert(ClientCredentialsGrant)
	if err != nil {
		panic(err)
	}
	id, err := strconv.Atoi(fmt.Sprintf("%d", res.ID()))
	if err != nil {
		panic(err)
	}
	ClientCredentialsGrant.ID = id

	_, err = collection.Insert(Client{
		Secret: generateClientSecret(),
		Name:   "Adele",
		Type:   "resource_owner_client_credentials",
	})
	if err != nil {
		panic(err)
	}

	_, err = collection.Insert(Client{
		Secret:      generateClientSecret(),
		Name:        "Adele",
		Type:        "authorization_grant",
		RedirectUrl: "https://localhost/callback",
	})
	if err != nil {
		panic(err)
	}

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
}
func tearDownClientTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users, oauth_clients, tokens, refresh_tokens, authorization_tokens CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}

func generateClientSecret() string {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
}
