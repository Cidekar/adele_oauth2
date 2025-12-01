package api

import (
	"net/http"

	up "github.com/upper/db/v4"
	"golang.org/x/crypto/bcrypt"
)

func (o *Service) GetUserByEmail(email string) (*User, error) {
	var user User

	collection := DB.Collection("users")
	res := collection.Find(up.Cond{"email =": email})

	err := res.One(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (o *Service) CheckUserPasswordMatches(plainText string, user User) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(plainText))
	if err != nil {
		return false
	}
	return true
}

// search for the suer in the session and return a bool if exists
func (o *Service) UserIsLoggedIn(r *http.Request) bool {

	uid := o.Session.Get(r.Context(), "userID")
	if uid != nil {
		return true
	}

	return false
}

// Get the current authenticated user
func (o *Service) GetAuthenticatedUser(r *http.Request) *User {

	uid := o.Session.Get(r.Context(), "userID")
	if uid != nil {
		var theUser User

		collection := DB.Collection("users")
		res := collection.Find(up.Cond{"id =": uid})

		err := res.One(&theUser)
		if err != nil {
			return nil
		}
		return &theUser
	}

	return nil
}
