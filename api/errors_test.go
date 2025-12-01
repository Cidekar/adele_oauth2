package api

import (
	"testing"
)

func TestOauth_Errors(t *testing.T) {

	e := NewErrorResponse(ErrInvalidRequest)

	if e.Description != Descriptions[ErrInvalidRequest] {
		t.Error("error description from new error response returned an unexpected value")
	}

	if e.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Error("status code from new error response returned an unexpected value")
	}

	if e.Error == Descriptions[ErrInvalidRequest] {
		t.Error("new error response returned an unexpected value")
	}
}
