package api

// ChallengeCodeValidate validates a PKCE code challenge and method per RFC 7636.
// The challenge method must be "S256" and the code must be 43-128 characters.
//
// Example:
//
//	ok, err := ChallengeCodeValidate("abc123...xyz", "S256")
//	if err != nil {
//		return nil, NewErrorResponse(err)
//	}
//
// Validation rules:
//   - method must be "S256" (plain is not supported)
//   - challengeCode must not be empty
//   - challengeCode length must be between 43 and 128 characters
func ChallengeCodeValidate(challengeCode, method string) (bool, error) {
	// only support S256, not plain
	if method != "S256" {
		return false, ErrUnsupportedCodeChallengeMethod
	}

	// code can not be empty
	if challengeCode == "" {
		return false, ErrCodeChallengeRequired
	}

	// the length of the "code_challenge" form field is outside the range of 43 to 128 (inclusive)
	codeLength := len(challengeCode)
	if !(codeLength >= 43 && codeLength <= 128) {
		return false, ErrInvalidCodeChallengeLen
	}
	return true, nil
}
