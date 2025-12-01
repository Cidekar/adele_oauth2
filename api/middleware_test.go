package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/cidekar/adele-framework"
	"github.com/cidekar/adele-framework/mux"
	"golang.org/x/crypto/bcrypt"
)

func TestOauth_Middleware(t *testing.T) {
	defer tearDownMiddlewareTest(ade)
	o := setupMiddlewareTest(t)

	// middleware
	// types
	if reflect.TypeOf(o.AuthenticationTokenMiddleware()).String() != "func(http.Handler) http.Handler" {
		t.Error("the authentication token middleware did not return a http.Handler type when it should have")
	}

	if reflect.TypeOf(o.AuthenticationCheckForScopes()).String() != "func(http.Handler) http.Handler" {
		t.Error("the authentication token middleware did not return a http.Handler type when it should have")
	}

	var ErrorLogger *log.Logger

	// bearer token middleware with config
	bm := BearerTokenHandler(o.Config.UnguardedRoutes, o.Config.GuardedRouteGroups, ErrorLogger, &o)

	if reflect.TypeOf(bm).String() != "func(http.Handler) http.Handler" {
		t.Error("the authentication token middleware did not return a http.Handler type when it should have")
	}

	// bearer
	// request/response - test redirect for non-json requests to guarded routes
	req := httptest.NewRequest("GET", o.Config.GuardedRouteGroups[0], nil)
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from next handler"))
	})

	handler := bm(nextHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status code %d, got %d when sending request without a accept/json header", http.StatusSeeOther, rr.Code)
	}

	location, _ := rr.Result().Location()
	if location.Path != "/" {
		t.Errorf("Expected redirect to %s, got %s when sending request without a accept/json header", "/", location.Path)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Accept", "application/json")
	rr = httptest.NewRecorder()
	handler = bm(nextHandler)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d when sending request to request outside a guarded route", http.StatusOK, rr.Code)
	}

	req = httptest.NewRequest("GET", o.Config.GuardedRouteGroups[0], nil)
	req.Header.Add("Accept", "application/json")
	rr = httptest.NewRecorder()
	handler = bm(nextHandler)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d when sending request to guarded route ", http.StatusUnauthorized, rr.Code)
	}

	req = httptest.NewRequest("GET", o.Config.UnguardedRoutes[0], nil)
	req.Header.Add("Accept", "application/json")
	rr = httptest.NewRecorder()
	handler = bm(nextHandler)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d when sending request to guarded route ", http.StatusOK, rr.Code)
	}

	req = httptest.NewRequest("GET", o.Config.GuardedRouteGroups[0], nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+OauthTkn.PlainText)
	rr = httptest.NewRecorder()
	handler = bm(nextHandler)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d when sending request to guarded route ", http.StatusOK, rr.Code)
	}

	// scope middleware
	sm := ScopeHandler([]string{}, []string{}, ErrorLogger, &o)

	if reflect.TypeOf(sm).String() != "func(http.Handler) http.Handler" {
		t.Error("the authentication token middleware did not return a http.Handler type when it should have")
	}

	// request / response
	sm = ScopeHandler(o.Config.UnguardedRoutes, o.Config.GuardedRouteGroups, ErrorLogger, &o)
	req = httptest.NewRequest("GET", "/", nil)
	rr = httptest.NewRecorder()

	nextHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	handler = sm(nextHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d when sending request to route without scopes attached", http.StatusOK, rr.Code)
	}

	req = httptest.NewRequest("GET", o.Config.GuardedRouteGroups[0], nil)
	ctx := context.WithValue(req.Context(), "accessToken", OauthTkn.PlainText)
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()
	handler = sm(nextHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d when sending request to route without scopes attached", http.StatusOK, rr.Code)
	}

	router := mux.NewRouter()
	router.Use(sm)
	pattern := "/api/foo/bar"
	annotation := "[scopes:Foo Bar]"
	router.Post(pattern+annotation, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r, _ := http.NewRequest("POST", pattern, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d when sending request to route without scopes attached", http.StatusOK, rr.Code)
	}

}

func setupMiddlewareTest(t *testing.T) Service {
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

	// Return properly initialized Service with config
	config := Configuration{
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

	// Seed the authorization token
	ot, err := o.GenerateOauthToken()
	if err != nil {
		panic(err)
	}
	ot.ClientID = ClientCredentialsGrant.ID
	ot.Expires = time.Now().UTC().Add(24 * time.Hour)

	collection = upper.Collection("tokens")
	_, err = collection.Insert(ot)
	if err != nil {
		panic(err)
	}

	OauthTkn = *ot

	return o
}

func tearDownMiddlewareTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users, oauth_clients, tokens, refresh_tokens, authorization_tokens CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}
