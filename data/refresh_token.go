package data

import (
	"bytes"
	"encoding/base64"
	"strconv"

	"github.com/harrisonde/oauth/api"
	"time"

	"github.com/google/uuid"
	up "github.com/upper/db/v4"
)

type RefreshToken struct {
	ID            int       `db:"id,omitempty" json:"id"`
	AccessTokenID int       `db:"access_token_id" json:"-"`
	Expires       time.Time `db:"expiry" json:"expiry"`
	Hash          []byte    `db:"token_hash" json:"-"`
	PlainText     string    `db:"token" json:"token"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at" json:"updated_at"`
	Api           *api.Service
}

func (c *RefreshToken) Table() string {
	return "refresh_tokens"
}

func (t *RefreshToken) Get(id int) (*RefreshToken, error) {
	var token RefreshToken
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"id": id})
	err := res.One(&token)
	if err == up.ErrNoMoreRows {
		return nil, nil
	}
	return &token, nil
}

func (t *RefreshToken) GetByToken(plainText string) (*RefreshToken, error) {
	var token RefreshToken
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": plainText})
	err := res.One(&token)
	if err != nil {
		if err == up.ErrNoMoreRows {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

// Generate a string representing the authorization granted to the client by the resource owner.  The string is usually opaque to the client. The token denotes an identifier used to retrieve the authorization information. https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
func (t *RefreshToken) GenerateToken(userID int, AccessTokenID int, clientID int) (*RefreshToken, error) {
	token := &RefreshToken{
		AccessTokenID: AccessTokenID,
		Expires:       api.GenerateTokenExpiry(24),
	}

	buf := bytes.NewBufferString(strconv.Itoa(clientID))
	buf.WriteString(strconv.Itoa(userID))
	buf.WriteString(strconv.FormatInt((time.Now()).UnixNano(), 10))

	uid := uuid.Must(uuid.NewRandom())
	sha := uuid.NewSHA1(uid, buf.Bytes()).String()

	token.Hash = []byte(sha)
	token.PlainText = base64.URLEncoding.EncodeToString([]byte(sha))

	return token, nil
}

func (t *RefreshToken) Insert(token RefreshToken) error {
	collection := upper.Collection(t.Table())

	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	_, err := collection.Insert(token)
	if err != nil {
		return err
	}
	return nil
}

func (t *RefreshToken) Delete(id int) error {
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"id": id})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

func (t *RefreshToken) DeleteByToken(plainText string) error {
	collection := upper.Collection(t.Table())
	res := collection.Find(up.Cond{"token": plainText})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}
