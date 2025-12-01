package api

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/google/uuid"
	up "github.com/upper/db/v4"
)

// Generate a string representing the authorization granted to the client by the resource owner.  The string is usually opaque to the client. The token denotes an identifier used to retrieve the authorization information. https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
func (o *Service) GenerateRefreshToken(userID int, AccessTokenID int, clientID int) (*RefreshToken, error) {
	token := &RefreshToken{
		AccessTokenID: AccessTokenID,
		Expires:       time.Now().UTC().Add(o.Config.RefreshTokenTokenTTL * time.Hour),
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

// Add a authorization token to the db and return the token id in the response
func (o *Service) InsertRefreshToken(token *RefreshToken) error {

	collection := DB.Collection("refresh_tokens")

	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	_, err := collection.Insert(token)
	if err != nil {
		return err
	}

	return nil
}

// Find a refresh token in the db by a given refresh token id.
func (o *Service) GetRefreshByToken(plainText string) (*RefreshToken, error) {
	var token RefreshToken

	collection := DB.Collection("refresh_tokens")
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

// Delete a refresh token from db by its plain text token
func (o *Service) DeleteRefreshTokenByToken(plainText string) error {

	collection := DB.Collection("refresh_tokens")
	res := collection.Find(up.Cond{"token": plainText})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}
