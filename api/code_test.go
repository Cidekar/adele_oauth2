package api

import (
	"testing"
)

func TestOauth_ChallengeCodeValidate(t *testing.T) {

	c, err := ChallengeCodeValidate("", "PlainText")
	if err == nil {
		t.Error("challenge code validate did not return nil error")
	}

	if c {
		t.Error("challenge code validate returned true when it should not have")
	}

	c, err = ChallengeCodeValidate("", "S256")
	if err == nil {
		t.Error("challenge code validate did not return nil error")
	}

	if c {
		t.Error("challenge code validate returned true when it should not have")
	}

	minChars := "abcdefghijklmnopqrstuvwxyz123456789abcdefgh"
	maxChars := "abcdefghijklmnopqrstuvwxyz123456789abcdefghabcdefghijklmnopqrstuvwxyz123456789abcdefghabcdefghijklmnopqrstuvwxyz123456789abcdefg"
	c, err = ChallengeCodeValidate(minChars, "S256")
	if err != nil {
		t.Error("challenge code validate return a error when it should not")
	}

	if c == false {
		t.Error("challenge code validate returned false when it should not have")
	}

	c, err = ChallengeCodeValidate(maxChars, "S256")
	if err != nil {
		t.Error("challenge code validate return a error when it should not")
	}

	if c == false {
		t.Error("challenge code validate returned false when it should not have")
	}

	c, err = ChallengeCodeValidate("123456789", "S256")
	if err == nil {
		t.Error("challenge code validate return a error when it should not")
	}

	if c != false {
		t.Error("challenge code validate returned false when it should not have")
	}

}
