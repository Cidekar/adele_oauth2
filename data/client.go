package data

import (
	"crypto/rand"
	"encoding/base32"
	"time"

	up "github.com/upper/db/v4"
)

// Client represents an OAuth2 client application stored in the database.
// Clients can be of various types: client_credentials, authorization_grant,
// authorization_grant_pkce, authorization_grant_pkce_implicit.
//
// Example:
//
//	client := data.Client{
//		Name:   "My Application",
//		UserID: 1,
//		Type:   "client_credentials",
//	}
//	id, secret, err := models.Clients.Insert(client)
type Client struct {
	ID        int       `db:"id,omitempty" json:"id"`
	UserID    int       `db:"user_id,omitempty" json:"user_id"`
	Secret    string    `db:"secret" json:"secret"`
	Name      string    `db:"name"`
	Revoked   int       `db:"revoked"`
	Type      string    `db:"type"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// Table returns the database table name for OAuth clients.
func (c *Client) Table() string {
	return "oauth_clients"
}

// CheckIsValid verifies that a client ID and secret match and the client is not revoked.
//
// Example:
//
//	client, _ := models.Clients.Get(1)
//	if client.CheckIsValid(1, "secret123") {
//		// Client is valid
//	}
func (c *Client) CheckIsValid(id int, secret string) bool {

	if c == nil {
		return false
	}

	if c.ID != id {
		return false
	}

	if c.Secret != secret {
		return false
	}

	if c.Revoked != 0 {
		return false
	}

	return true
}

// Invalidate revokes a client by setting its Revoked flag to 1.
// Revoked clients cannot authenticate or obtain tokens.
//
// Example:
//
//	err := models.Clients.Invalidate(clientID)
//	// Client can no longer authenticate
func (c *Client) Invalidate(id int) error {
	var theClient Client
	collection := upper.Collection(c.Table())
	res := collection.Find(up.Cond{"id =": id})

	err := res.One(&theClient)
	if err != nil {
		return err
	}

	theClient.Revoked = 1

	err = res.Update(&theClient)
	if err != nil {
		return err
	}

	return nil
}

// GetBySecret retrieves a client by its secret key.
//
// Example:
//
//	client, err := models.Clients.GetBySecret("ABCDEFGHIJKLMNOP")
func (c *Client) GetBySecret(secret string) (*Client, error) {

	var theClient Client
	collection := upper.Collection(c.Table())
	res := collection.Find(up.Cond{"secret =": secret})
	err := res.One(&theClient)
	if err != nil {
		return nil, err
	}

	return &theClient, nil
}

// Get retrieves a client by its ID. Returns nil if not found.
//
// Example:
//
//	client, err := models.Clients.Get(1)
//	if client == nil {
//		// Client not found
//	}
func (c *Client) Get(id int) (*Client, error) {
	var theClient Client
	collection := upper.Collection(c.Table())
	res := collection.Find(up.Cond{"id =": id})

	err := res.One(&theClient)
	if err != nil {
		// If no client is found, return nil and no error
		if err == up.ErrNoMoreRows {
			return nil, nil
		}
		return nil, err
	}

	return &theClient, nil
}

// All retrieves all clients belonging to a specific user.
//
// Example:
//
//	clients, err := models.Clients.All(userID)
//	for _, client := range *clients {
//		fmt.Println(client.Name)
//	}
func (c *Client) All(id int) (*[]Client, error) {
	var Clients []Client
	collection := upper.Collection(c.Table())
	res := collection.Find(up.Cond{"user_id =": id})

	err := res.All(&Clients)
	if err != nil {
		return nil, err
	}

	return &Clients, nil
}

func (c *Client) Update(theClient Client) error {
	theClient.UpdatedAt = time.Now()
	collection := upper.Collection(c.Table())
	res := collection.Find(theClient.ID)

	err := res.Update(&theClient)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Delete(id int) error {
	collection := upper.Collection(c.Table())
	res := collection.Find(id)
	err := res.Delete()

	if err != nil {
		return err
	}

	return nil
}

// Insert creates a new client with an auto-generated secret.
// Returns the new client ID and the generated secret.
//
// Example:
//
//	client := data.Client{Name: "My App", UserID: 1, Type: "client_credentials"}
//	id, secret, err := models.Clients.Insert(client)
//	// Save the secret - it cannot be retrieved later!
//	fmt.Printf("Client ID: %d, Secret: %s\n", id, secret)
func (c *Client) Insert(client Client) (int, string, error) {

	newSecret, err := c.GenerateSecret()
	if err != nil {
		return 0, "", err
	}

	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()
	client.Secret = newSecret

	collection := upper.Collection(c.Table())
	res, err := collection.Insert(client)
	if err != nil {
		return 0, "", err
	}

	id := getInsertID(res.ID())

	return id, newSecret, nil
}

// GenerateSecret creates a cryptographically secure random secret for a client.
//
// Example:
//
//	secret, err := models.Clients.GenerateSecret()
//	// secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
func (c *Client) GenerateSecret() (string, error) {

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	return secret, nil
}
