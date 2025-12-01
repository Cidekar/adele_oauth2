package api

import (
	"testing"
	"time"
)

func TestOauth_Token_Is_Expired(t *testing.T) {

	o := Service{}
	at := AuthorizationToken{
		Expires: time.Now().UTC().Add(24 * time.Hour),
	}
	ot := OauthToken{
		Expires: time.Now().UTC().Add(24 * time.Hour),
	}
	rt := RefreshToken{
		Expires: time.Now().UTC().Add(24 * time.Hour),
	}
	type UnknownToken struct{}
	ut := UnknownToken{}

	ok := o.TokenIsExpired(at)
	if !ok {
		t.Error("token is expired when it should not be")
	}

	ok = o.TokenIsExpired(ot)
	if !ok {
		t.Error("token is expired when it should not be")
	}

	ok = o.TokenIsExpired(rt)
	if !ok {
		t.Error("token is expired when it should not be")
	}

	ok = o.TokenIsExpired(ut)
	if ok {
		t.Error("token is not expired when it should not be")
	}

}
