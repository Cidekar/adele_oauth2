package api

import (
	"reflect"
	"time"
)

// TokenIsExpired checks if the provided token has expired by comparing its 'Expires' field
// with the current UTC time. Returns true if the token is still valid (not expired),
// false if expired or if the token doesn't have an Expires field.
//
// Example:
//
//	token := &OauthToken{Expires: time.Now().Add(1 * time.Hour)}
//	if facades.TokenIsExpired(token) {
//		fmt.Println("Token is still valid")
//	}
func (o *Service) TokenIsExpired(token interface{}) bool {
	return IsExpired(token)
}

// GenerateTokenExpiry creates a token expiry time for use with any type of tokens
// issued by the authorization server. Currently returns 24 hours from now in UTC.
//
// Example:
//
//	expiry := facades.GenerateTokenExpiry(24)
//	token.Expires = expiry
func GenerateTokenExpiry(hours int) time.Time {
	return time.Now().UTC().Add(24 * time.Hour)
}

// IsExpired checks if the provided token has expired by comparing its 'Expires' field
// with the current UTC time. Returns true if still valid, false if expired.
// Works with any struct that has an Expires field of type time.Time.
//
// Example:
//
//	token := &OauthToken{Expires: time.Now().Add(-1 * time.Hour)} // expired
//	if !IsExpired(token) {
//		fmt.Println("Token has expired")
//	}
func IsExpired(token interface{}) bool {
	var expires time.Time
	rv := reflect.ValueOf(token)

	// Handle pointer types by dereferencing
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	// Access the 'Expires' field and return false if it does not exist or is of the wrong typ
	expiresField := rv.FieldByName("Expires")
	if !expiresField.IsValid() || expiresField.Type() != reflect.TypeOf(expires) {
		return false
	}

	expires = expiresField.Interface().(time.Time)

	now := time.Now().UTC()
	return expires.After(now)
}
