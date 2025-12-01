package api

import (
	"testing"
)

func TestOauth_Scopes(t *testing.T) {

	o := Service{}

	var (
		bad  = " ping pong  oops"
		good = "ping pong long"

		config = Configuration{
			Scopes: map[string]string{
				"ping": "Allows access to the ping resource",
				"pong": "Allows access to the pong resource",
			},
		}
	)

	o.Config = config

	ok, err := scopesValidate(bad)
	if err == nil {
		t.Errorf("invalid scope string %s passed validation when it should not", bad)
	}
	if ok {
		t.Errorf("expected bad scope format %s, got true when it should be false", bad)
	}

	ok, err = scopesValidate(good)
	if err != nil {
		t.Errorf("valid scope string %s failed validation when it should not", good)
	}
	if !ok {
		t.Errorf("expected a valid scope format %s got false when it should not", good)
	}

	sf, err := scopesMapToString(config.Scopes)
	if err != nil {
		t.Errorf("converting scope map to string returned an error when it should not")
	}

	// Map iteration order is non-deterministic, so check both possible orderings
	if sf != "ping pong" && sf != "pong ping" {
		t.Errorf("converting scope map to string returned invalid string: %s", sf)
	}

	s := []string{"ping", "pong"}
	ok = o.scopesCanBeIssued(s)

	if !ok {
		t.Errorf("not able to issue scope %v when it should be able to", s)
	}

	s = []string{"ping", "pong", "foo"}
	ok = o.scopesCanBeIssued(s)

	if ok {
		t.Errorf("able to issue scope %v when it should not", s)
	}
}
