package data

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	up "github.com/upper/db/v4"
)

var (
	ttl = 24 * time.Hour
)

// Token represents an OAuth2 access token stored in the database.
//
// Example:
//
//	token, err := models.Tokens.GenerateToken()
//	token.ClientID = client.ID
//	token.Scopes = "read write"
//	token, err = models.Tokens.Insert(token)
type Token struct {
	ID           int       `db:"id,omitempty" json:"id"`
	UserID       int       `db:"user_id,omitempty" json:"user_id"`
	ClientID     int       `db:"client_id" json:"client_id"`
	PlainText    string    `db:"token" json:"token"`
	Hash         []byte    `db:"token_hash" json:"-"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
	Expires      time.Time `db:"expiry" json:"expiry"`
	RefreshToken string    `db:"-" json:"refresh_token"`
	Scopes       string    `db:"scopes,omitempty" json:"scopes"`
}

// TODO: Need to simply add the token field to the user model in the consumer.
type User struct {
	ID        int       `db:"id,omitempty"`
	FirstName string    `db:"first_name"`
	LastName  string    `db:"last_name"`
	Email     string    `db:"email"`
	Active    int       `db:"user_active"`
	Password  string    `db:"password"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
	Token     Token     `db:"-"`
}

// All scopes supported by the authorization server.
// Example:
// "ping": "Allows access to the ping resource",
// "pong": "Allows to the pong resource",
var Scopes = map[string]string{}

// Routes supported by the authorization server that do not require an access token.
var UnguardedRoutes = []string{
	"/oauth/token",
	"/oauth/token/refresh",
}

// AnyScope checks if the token has at least one of the required scopes.
// Returns true if any scope matches, false otherwise.
//
// Example:
//
//	if data.AnyScope(r, []string{"read", "write"}) {
//		// Token has read OR write scope
//	}
func AnyScope(r *http.Request, scopes []string) bool {
	token := GetTokenFromRequest(r)
	if token == nil {
		return false
	}

	tokenScopes := strings.Split(token.Scopes, " ")
	for Sk, _ := range tokenScopes {
		for sv := range scopes {
			if Sk == sv {
				return true
			}
		}
	}
	return false
}

// HasScope checks if the token has ALL of the required scopes.
// Returns true only if every scope is present, false otherwise.
//
// Example:
//
//	if data.HasScope(r, []string{"read", "write"}) {
//		// Token has BOTH read AND write scopes
//	}
func HasScope(r *http.Request, scopes []string) bool {
	token := GetTokenFromRequest(r)
	if token == nil {
		return false
	}

	ok := true
	tokenScopes := strings.Split(token.Scopes, " ")
	for _, s := range scopes {
		if !slices.Contains(tokenScopes, s) {
			ok = false
			break
		}
	}

	return ok
}

// Table returns the database table name for tokens.
func (t *Token) Table() string {
	return "tokens"
}

// GetUserForToken retrieves the user associated with a given token string.
//
// Example:
//
//	user, err := models.Tokens.GetUserForToken("token_string")
//	if err != nil {
//		// Token not found or user not found
//	}
func (t *Token) GetUserForToken(token string) (*User, error) {
	var u User
	var theToken Token

	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": token})
	err := res.One(&theToken)
	if err != nil {
		return nil, err
	}

	collection = upper.Collection("users")
	res = collection.Find(up.Cond{"id": theToken.UserID})

	u.Token = theToken

	return &u, nil
}

func (t *Token) GetTokensForUser(id int) ([]*Token, error) {
	var tokens []*Token
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"user_id": id})
	err := res.All(&tokens)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (t *Token) Get(id int) (*Token, error) {
	var token Token
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"id": id})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (t *Token) GetByToken(plainText string) (*Token, error) {
	var token Token
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": plainText})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (t *Token) Delete(id int) error {
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"id": id})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

func (t *Token) DeleteByToken(plainText string) error {
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": plainText})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

func (t *Token) Insert(token *Token) (*Token, error) {
	collection := upper.Collection(t.Table())

	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	res, err := collection.Insert(token)
	if err != nil {
		return nil, err
	}

	id, err := strconv.Atoi(fmt.Sprintf("%d", res.ID()))
	if err != nil {
		return nil, err
	}

	token.ID = id

	return token, nil
}

// GenerateToken creates a new token with a cryptographically secure random value.
// The token expires after 24 hours by default.
//
// Example:
//
//	token, err := models.Tokens.GenerateToken()
//	token.ClientID = 1
//	token.Scopes = "read"
//	token, err = models.Tokens.Insert(token)
func (t *Token) GenerateToken() (*Token, error) {
	token := &Token{
		Expires: time.Now().Add(ttl),
	}

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	// Create a token that is always the same length each time we create one.
	token.PlainText = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(token.PlainText))
	token.Hash = hash[:]

	return token, nil
}

// AuthenticateToken validates a bearer token from the HTTP Authorization header.
// Checks that the token exists, is not expired, and belongs to a valid user (if user-bound).
//
// Example:
//
//	ok, err := models.Tokens.AuthenticateToken(r)
//	if err != nil {
//		// Invalid or expired token
//	}
func (t *Token) AuthenticateToken(r *http.Request) (bool, error) {
	token, err := t.GetAuthTokenFromHeader(r)
	if err != nil {
		return false, err
	}

	if token.Expires.Before(time.Now()) {
		return false, errors.New("expired token")
	}

	if token.UserID != 0 {
		_, err := t.GetUserForToken(token.PlainText)
		if err != nil {
			return false, errors.New("no matching user found")
		}
	}

	return false, nil
}

// fingerprint the token and ensure it is a valid token
func (t *Token) ValidToken(token string) (bool, error) {
	user, err := t.GetUserForToken(token)
	if err != nil {
		return false, errors.New("no matching user found")
	}

	if user.Token.PlainText == "" {
		return false, errors.New("no matching token found")
	}

	if user.Token.Expires.Before(time.Now()) {
		return false, errors.New("expired token")
	}

	return true, nil
}

// GetAuthTokenFromHeader extracts and validates a bearer token from the Authorization header.
// Expected format: "Authorization: Bearer <token>"
//
// Example:
//
//	// Request header: Authorization: Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ
//	token, err := models.Tokens.GetAuthTokenFromHeader(r)
//	fmt.Println(token.Scopes) // "read write"
func (t *Token) GetAuthTokenFromHeader(r *http.Request) (*Token, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return nil, errors.New("no authorization header received")
	}

	headerParts := strings.Split(authorizationHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return nil, errors.New("no authorization header received")
	}

	token := headerParts[1]

	if len(token) != 26 {
		return nil, errors.New("token is wrong size")
	}

	tkn, err := t.GetByToken(token)
	if err != nil {
		return nil, errors.New("no matching token found")
	}

	return tkn, nil
}

// GetTokenFromRequest extracts the token from the request context.
// The token must have been previously set by the AuthToken middleware.
//
// Example:
//
//	// In a handler after AuthToken middleware:
//	token := data.GetTokenFromRequest(r)
//	if token != nil {
//		fmt.Println(token.Scopes)
//	}
func GetTokenFromRequest(r *http.Request) *Token {
	ctx := r.Context()
	accessTokenID, ok := ctx.Value("accessToken").(string)
	if !ok {
		return nil
	}

	var accessToken Token
	collection := upper.Collection("tokens")
	res := collection.Find(up.Cond{"token": accessTokenID})
	err := res.One(&accessToken)
	if err != nil {
		return nil
	}

	return &accessToken
}
