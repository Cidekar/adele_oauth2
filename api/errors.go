package api

import (
	"errors"
)

// OAuth2 error types per RFC 6749 Section 5.2.
// Use these with NewErrorResponse to create properly formatted error responses.
//
// Example:
//
//	if client == nil {
//		return nil, NewErrorResponse(ErrInvalidClient)
//	}
var (
	ErrInvalidRequest                 = errors.New("invalid_request")
	ErrUnauthorizedClient             = errors.New("unauthorized_client")
	ErrAccessDenied                   = errors.New("access_denied")
	ErrUnsupportedResponseType        = errors.New("unsupported_response_type")
	ErrInvalidScope                   = errors.New("invalid_scope")
	ErrServerError                    = errors.New("server_error")
	ErrTemporarilyUnavailable         = errors.New("temporarily_unavailable")
	ErrInvalidClient                  = errors.New("invalid_client")
	ErrInvalidGrant                   = errors.New("invalid_grant")
	ErrUnsupportedGrantType           = errors.New("unsupported_grant_type")
	ErrCodeChallengeRequired          = errors.New("invalid_request")
	ErrUnsupportedCodeChallengeMethod = errors.New("invalid_request")
	ErrInvalidCodeChallengeLen        = errors.New("invalid_request")
	ErrInvalidCodeChallenge           = errors.New("invalid code challenge")
	ErrExpiredRefreshToken            = errors.New("expired refresh token")
	ErrInvalidRefreshToken            = errors.New("invalid refresh token")
	ErrInvalidRedirectURI             = errors.New("invalid redirect uri")
)

// descriptions are base on https://github.com/go-oauth2/oauth2/blob/master/errors/response.go and follow RFC 6749
var Descriptions = map[error]string{
	ErrInvalidRequest:                 "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	ErrUnauthorizedClient:             "The client is not authorized to request an authorization code using this method.",
	ErrAccessDenied:                   "The resource owner or authorization server denied the request.",
	ErrUnsupportedResponseType:        "The authorization server does not support obtaining an authorization code using this method.",
	ErrInvalidScope:                   "The requested scope is invalid, unknown, or malformed.",
	ErrServerError:                    "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	ErrTemporarilyUnavailable:         "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
	ErrInvalidClient:                  "Client authentication failed.",
	ErrInvalidGrant:                   "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	ErrUnsupportedGrantType:           "The authorization grant type is not supported by the authorization server.",
	ErrCodeChallengeRequired:          "PKCE is required. code_challenge is missing.",
	ErrUnsupportedCodeChallengeMethod: "Selected code_challenge_method not supported.",
	ErrInvalidCodeChallengeLen:        "Code challenge length must be between 43 and 128 characters.",
	ErrInvalidRedirectURI:             "The redirect URI provided is not a valid URI.",
}

// status codes are based on https://github.com/go-oauth2/oauth2/blob/master/errors/response.go and follow RFC 6749
var StatusCodes = map[error]int{
	ErrInvalidRequest:                 400,
	ErrUnauthorizedClient:             401,
	ErrAccessDenied:                   403,
	ErrUnsupportedResponseType:        401,
	ErrInvalidScope:                   400,
	ErrServerError:                    500,
	ErrTemporarilyUnavailable:         503,
	ErrInvalidClient:                  401,
	ErrInvalidGrant:                   400,
	ErrUnsupportedGrantType:           400,
	ErrCodeChallengeRequired:          400,
	ErrUnsupportedCodeChallengeMethod: 400,
	ErrInvalidCodeChallengeLen:        400,
	ErrInvalidCodeChallenge:           401,
	ErrInvalidRefreshToken:            401,
	ErrExpiredRefreshToken:            401,
	ErrInvalidRedirectURI:             400,
}

// NewErrorResponse creates an ErrorResponse from an error type.
// Maps the error to its RFC 6749 description and HTTP status code.
//
// Example:
//
//	err := NewErrorResponse(ErrInvalidClient)
//	// err.Error = "invalid_client"
//	// err.Description = "Client authentication failed."
//	// err.ErrorCode = 401
//
//	// Use with JSON response:
//	w.WriteHeader(err.ErrorCode)
//	json.NewEncoder(w).Encode(err)
//
// Note: ErrorCode is used for HTTP status only and is not included in the JSON response.
// The JSON output uses error_description (Description) and error_uri (URI) per RFC 6749.
func NewErrorResponse(err error) *ErrorResponse {
	return &ErrorResponse{
		Description: Descriptions[err],
		Error:       err.Error(),
		ErrorCode:   StatusCodes[err],
	}
}
