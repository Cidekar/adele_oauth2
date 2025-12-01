package api

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cidekar/adele-framework"
)

func TestOauth_AuthorizationToken(t *testing.T) {
	defer tearDownAuthorizationTest(ade)
	o := setupAuthorizationTest(t)

	at, err := o.GenerateAuthorizationToken()
	if err != nil {
		t.Error("generate authorization token returned an error when it should not")
	}

	if at == &(AuthorizationToken{}) {
		t.Error("generate authorization token returned an empty struct when it should not")
	}

	at.ClientID = ClientCredentialsGrant.ID
	at.Expires = time.Now().UTC().Add(24 * time.Hour)
	at.ChallengeCode = "UBB78fYX20Qg8kvVMS_upMzmy1Qibvm2gphIBrOSbZU"

	at, err = o.InsertAuthorizationToken(at)
	if err != nil {
		t.Error("insert authorization token returned an error when it should not")
	}

	_, err = o.GetAuthorizationTokenByToken(at.PlainText)
	if err != nil {
		t.Error("get authorization token returned an error when it should not")
	}

	codeVerifier := "xuDagaErmffpBPRyKGvpf0MVYeAynexTODe69MvFsxI8ftz"
	ok := o.VerifyAuthorizationCode(*at, codeVerifier)
	if !ok {
		t.Error("verify authorization token returned false when it should not")
	}

	err = o.DeleteAuthorizationToken(at.ID)
	if err != nil {
		t.Error("get oauth token returned an error when it should not")
	}
}

func setupAuthorizationTest(t *testing.T) Service {
	// Run migrations via raw SQL
	upBytes, err := templateFS.ReadFile("testmigrations/oauth_test_postgres.sql")
	if err != nil {
		panic(err)
	}

	_, err = upper.SQL().Exec(string(upBytes))
	if err != nil {
		panic(err)
	}

	// Seed client
	ClientCredentialsGrant = Client{
		Secret: generateClientSecret(),
		Name:   "Adele",
		Type:   "client_credentials",
	}

	collection := upper.Collection("oauth_clients")
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

func tearDownAuthorizationTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users, oauth_clients, tokens, refresh_tokens, authorization_tokens CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}
