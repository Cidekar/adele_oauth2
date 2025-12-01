package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	up "github.com/upper/db/v4"
)

// Create a oauth token that is always the same length each time one is generated.
func (o *Service) GenerateOauthToken() (*OauthToken, error) {
	token := &OauthToken{
		Expires: time.Now().UTC().Add(o.Config.OauthTokenTTL * time.Hour),
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

// Add a token to the db and return the token id in the response
func (o *Service) InsertOauthToken(token *OauthToken) (*OauthToken, error) {

	collection := DB.Collection("tokens")

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

func (o *Service) GetOauthToken(id int) (*OauthToken, error) {

	collection := DB.Collection("tokens")

	var token OauthToken
	res := collection.Find(up.Cond{"id": id})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (o *Service) DeleteOauthToken(id int) error {

	collection := DB.Collection("tokens")
	res := collection.Find(up.Cond{"id": id})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

// token authentication attached to a http request in the form of bearer token.
func (o *Service) AuthenticateToken(r *http.Request) (bool, *OauthToken, error) {
	token, err := o.GetAuthTokenFromHeader(r)
	if err != nil {
		return false, nil, err
	}

	ok := o.TokenIsExpired(token)
	if !ok {
		return false, nil, errors.New("expired token")
	}

	return true, token, nil
}

// get the token from the db by the plain text value
func (o *Service) GetByToken(plainText string) (*OauthToken, error) {

	collection := DB.Collection("tokens")

	var token OauthToken

	res := collection.Find(up.Cond{"token": plainText})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// extract a token from the http request header
func (o *Service) GetAuthTokenFromHeader(r *http.Request) (*OauthToken, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return nil, errors.New("no authorization header received")
	}

	headerParts := strings.Split(authorizationHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return nil, errors.New("invalid authorization header received")
	}

	token := headerParts[1]

	if len(token) != 26 {
		return nil, errors.New("token is wrong size")
	}

	tkn, err := o.GetByToken(token)
	if err != nil {
		return nil, errors.New("no matching token found")
	}

	return tkn, nil
}
