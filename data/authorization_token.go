package data

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strconv"

	"github.com/harrisonde/oauth/api"
	"time"

	up "github.com/upper/db/v4"
)

type AuthorizationToken struct {
	ID                  int       `db:"id,omitempty" json:"id"`
	UserID              *int      `db:"user_id,omitempty" json:"user_id"`
	ClientID            int       `db:"client_id" json:"client_id"`
	PlainText           string    `db:"token" json:"token"`
	Hash                []byte    `db:"token_hash" json:"-"`
	CreatedAt           time.Time `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time `db:"updated_at" json:"updated_at"`
	Expires             time.Time `db:"expiry" json:"expiry"`
	ChallengeCode       string    `db:"challenge_code,omitempty" json:"ChallengeCode"`
	ChallengeCodeMethod string    `db:"challenge_code_method,omitempty" json:"ChallengeCodeMethod"`
	State               string    `db:"-" json:"state"`
	Api                 *api.Service
}

func (t *AuthorizationToken) Table() string {
	return "authorization_tokens"
}

func (t *AuthorizationToken) Get(id int) (*AuthorizationToken, error) {
	var token AuthorizationToken
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"id": id})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (t *AuthorizationToken) GetByToken(plainText string) (*AuthorizationToken, error) {
	var token AuthorizationToken
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": plainText})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (t *AuthorizationToken) Delete(id int) error {
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"id": id})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

func (t *AuthorizationToken) DeleteByToken(plainText string) error {
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": plainText})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

func (t *AuthorizationToken) Insert(token *AuthorizationToken) (*AuthorizationToken, error) {
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

func (t *AuthorizationToken) GenerateToken() (*AuthorizationToken, error) {
	token := &AuthorizationToken{
		Expires: api.GenerateTokenExpiry(24),
	}

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	token.PlainText = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(token.PlainText))
	token.Hash = hash[:]

	return token, nil
}
