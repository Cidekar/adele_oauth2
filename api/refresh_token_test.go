package api

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cidekar/adele-framework"
	"golang.org/x/crypto/bcrypt"
)

func TestOauth_RefreshToken(t *testing.T) {
	defer tearDownRefreshTest(ade)
	o := setupRefreshTokenTest(t)

	rt, err := o.GenerateRefreshToken(1, 1, 1)
	if err != nil {
		t.Error("generate refresh token returned an error when it should not")
	}

	if rt == &(RefreshToken{}) {
		t.Error("generate refresh token returned an empty struct when it should not")
	}

	err = o.InsertRefreshToken(rt)
	if err != nil {
		t.Error("insert refresh token returned an error when it should not")
	}

	err = o.DeleteRefreshTokenByToken(rt.PlainText)
	if err != nil {
		t.Error("get oauth token returned an error when it should not")
	}
}

func setupRefreshTokenTest(t *testing.T) Service {
	// Run migrations via raw SQL
	upBytes, err := templateFS.ReadFile("testmigrations/oauth_test_postgres.sql")
	if err != nil {
		panic(err)
	}

	_, err = upper.SQL().Exec(string(upBytes))
	if err != nil {
		panic(err)
	}

	// Seed User
	passHash, err := bcrypt.GenerateFromPassword([]byte("Password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	collection := upper.Collection("users")
	_, err = collection.Insert(User{
		Email:     "adele@localhost.net",
		FirstName: "Adele",
		LastName:  "Wiring Code",
		Password:  string(passHash),
	})
	if err != nil {
		panic(err)
	}

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
	o := NewWithConfig(&ade, config)

	// Seed token
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

func tearDownRefreshTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users, oauth_clients, tokens, refresh_tokens, authorization_tokens CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}
