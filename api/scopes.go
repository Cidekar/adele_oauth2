package api

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// validate user controlled scopes provided by a grant client. Ensure the input is a string of alpha-numeric characters separated with whitespaces.
func scopesValidate(scopes string) (bool, error) {
	rawScopes := strings.TrimSpace(scopes)
	if rawScopes == "" {
		return true, nil
	}

	re := regexp.MustCompile("^[a-zA-Z0-9]+( [a-zA-Z0-9]+)*$")

	if !re.MatchString(rawScopes) {
		return false, fmt.Errorf("%s is not a valid scope string", rawScopes)
	}

	return true, nil
}

// format a delimited string of scopes into a slice
func scopesFormat(scopes string) []string {
	scopes = strings.TrimSpace(scopes)
	if scopes == "" {
		return nil
	}

	return strings.Split(strings.TrimSpace(scopes), " ")
}

// iterate through a map of scopes and return a string of scopes with a white space separator and ensure each scope is alpha numeric string
func scopesMapToString(scopes map[string]string) (string, error) {
	re := regexp.MustCompile("^[a-zA-Z0-9-]*$")

	var scopeString []string
	for k := range scopes {
		if !re.MatchString(k) {
			return "", fmt.Errorf("the scopes provided to the authorization server are not alphanumeric; the key \"%s\" is not a valid scope", k)
		}
		scopeString = append(scopeString, strings.TrimSpace(k))
	}

	return strings.Join(scopeString, " "), nil
}

// determine if the authorization sever allowed to issue the requested scope to the client.
func (o *Service) scopesCanBeIssued(scopes []string) bool {
	for _, s := range scopes {
		_, ok := o.Config.Scopes[s]
		if !ok {
			return false
		}
	}
	return true
}

// Check if the token in the request has all scope(s)
func (o *Service) HasScope(r *http.Request, requiredScopes Scopes) bool {
	ok, token, err := o.AuthenticateToken(r)
	if err != nil || !ok {
		return false
	}

	ts := scopesFormat(token.Scopes)
	rs, err := scopesMapToString(requiredScopes)
	if err != nil {
		return false
	}
	for _, s := range scopesFormat(rs) {
		if !slices.Contains(ts, s) {
			return false
		}
	}

	return true

}

// Check if the token has at least one scope.
func (o *Service) AnyScope(r *http.Request, anyScopes Scopes) bool {
	ok, token, err := o.AuthenticateToken(r)
	if err != nil || !ok {
		return false
	}

	ts := scopesFormat(token.Scopes)
	as, err := scopesMapToString(anyScopes)
	if err != nil {
		return false
	}
	for _, s := range scopesFormat(as) {
		if slices.Contains(ts, s) {
			return true
		}
	}
	return false
}
