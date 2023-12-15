package schemas

import (
	"github.com/VinukaThejana/auth/models"
	"github.com/google/uuid"
)

// User is schema that contians user freindly user details
type User struct {
	ID               *uuid.UUID `json:"id"`
	Name             string     `json:"name"`
	Username         string     `json:"username"`
	Email            string     `json:"email"`
	PhotoURL         string     `json:"photo_url"`
	TwoFactorEnabled bool       `json:"two_factor_enabled"`
}

// FilterUser is a function that is used to filter the user model to a user freindly format
func FilterUser(user models.User) User {
	return User{
		ID:               user.ID,
		Name:             user.Name,
		Username:         user.Username,
		Email:            user.Email,
		PhotoURL:         user.PhotoURL,
		TwoFactorEnabled: user.TwoFactorEnabled,
	}
}
