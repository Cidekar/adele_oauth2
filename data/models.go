package data

import (
	"fmt"

	"github.com/cidekar/adele-framework"
	db2 "github.com/upper/db/v4"
)

var upper db2.Session

// Models aggregates all OAuth2 data models for convenient access.
//
// Example:
//
//	models := data.New(adeleApp)
//	client, err := models.Clients.Get(1)
//	token, err := models.Tokens.GenerateToken()
type Models struct {
	Clients      Client
	Tokens       Token
	RefreshToken RefreshToken
}

// New creates a new Models instance with the given Adele application.
// Initializes the database session for all model operations.
//
// Example:
//
//	models := data.New(adeleApp)
func New(a *adele.Adele) Models {
	// Set the upper's session
	upper = a.DB.NewSession()

	// Return the models
	return Models{
		Clients:      Client{},
		Tokens:       Token{},
		RefreshToken: RefreshToken{},
	}
}

// getInsertID handles different database ID return types (int vs int64).
// Postgres returns int64, other databases may return int.
//
// Example:
//
//	res, _ := collection.Insert(record)
//	id := getInsertID(res.ID())
func getInsertID(i db2.ID) int {
	idType := fmt.Sprintf("%T", i) // get type

	// Postgres
	if idType == "int64" {
		return int(i.(int64))
	}

	// Anything else
	return i.(int)
}
