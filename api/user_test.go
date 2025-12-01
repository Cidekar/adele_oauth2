package api

import (
	"fmt"
	"testing"

	"github.com/cidekar/adele-framework"
	"golang.org/x/crypto/bcrypt"
)

func TestOauth_User(t *testing.T) {
	defer tearDownUserTest(ade)
	o := setupUserTest(t)

	u, err := o.GetUserByEmail("adele@localhost.net")
	if err != nil {
		t.Error("get user by email returned a error when it should not")
	}

	ui := &User{}
	if u == ui {
		t.Error("get user by email did not return a user")
	}

	match := o.CheckUserPasswordMatches("Password", *u)
	if match == false {
		t.Error("check user password matches returned false when it should not")
	}

}

func setupUserTest(t *testing.T) Service {
	// Run migrations via raw SQL
	upBytes, err := templateFS.ReadFile("testmigrations/user_table.postgres.sql")
	if err != nil {
		panic(err)
	}

	_, err = upper.SQL().Exec(string(upBytes))
	if err != nil {
		panic(err)
	}

	// seed user
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

func tearDownUserTest(_ adele.Adele) {
	_, err := upper.SQL().Exec("DROP TABLE IF EXISTS schema_migration, users CASCADE;")
	if err != nil {
		fmt.Println(err)
	}
}
