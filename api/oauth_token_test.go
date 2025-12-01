package api

import (
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cidekar/adele-framework"
	"golang.org/x/crypto/bcrypt"
)

func TestOauth_OauthToken(t *testing.T) {
	defer tearDownOauthTest(ade)
	o := setupOauthTest(t)

	ot, err := o.GenerateOauthToken()
	if err != nil {
		t.Error("generate oauth token returned an error when it should not")
	}

	if ot == &(OauthToken{}) {
		t.Error("generate oauth token returned an empty struct when it should not")
	}

	ot.ClientID = ClientCredentialsGrant.ID
	ot.Expires = time.Now().UTC().Add(24 * time.Hour)

	ot, err = o.InsertOauthToken(ot)
	if err != nil {
		t.Error("insert oauth token returned an error when it should not")
	}

	_, err = o.GetOauthToken(ot.ID)
	if err != nil {
		t.Error("get oauth token returned an error when it should not")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+ot.PlainText)
	ok, tkn, err := o.AuthenticateToken(req)
	if err != nil {
		fmt.Println(err)
		t.Error("get authenticate token returned an error when it should not")
	}

	if !ok {
		t.Error("get authenticate token returned false when it should be true")
	}

	if tkn == nil {
		t.Error("get authenticate token returned a nil when it should be a *OauthToken")
	}

	_, err = o.GetAuthTokenFromHeader(req)
	if err != nil {
		t.Error("get token from header returned an error when it should not")
	}

	_, err = o.GetByToken(ot.PlainText)
	if err != nil {
		t.Error("get oauth token returned an error when it should not")
	}

	err = o.DeleteOauthToken(ot.ID)
	if err != nil {
		t.Error("get oauth token returned an error when it should not")
	}
}

func setupOauthTest(t *testing.T) Service {
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

	// Return properly initialized Service
	config := Configuration{
		Scopes: map[string]string{
			"ping": "Allows access to the ping resource",
		},
		AuthorizationTokenTTL: 60,
		OauthTokenTTL:         24,
		RefreshTokenTokenTTL:  24,
	}
	return NewWithConfig(&ade, config)
}

func tearDownOauthTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users, oauth_clients, tokens, refresh_tokens, authorization_tokens CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}
