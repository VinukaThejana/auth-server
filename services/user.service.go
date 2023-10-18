package services

import (
	"strings"

	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User contains all the user related services
type User struct {
	Conn *connect.Connector
}

// IsEmailAvailable is a function that is used to find out wether the email address is verified or not
func (u *User) IsEmailAvailable(email string) (
	userID *uuid.UUID,
	isEmailAvailable,
	isEmailVerified bool,
	err error,
) {
	var user models.User
	err = u.Conn.DB.Select("id", "email", "verified").Where(&models.User{
		Email: email,
	}).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, true, false, nil
		}

		return nil, false, false, err
	}

	return user.ID, false, user.Verified, nil
}

// IsUsernameAvailable is a function that is used to check wether a username is available
func (u *User) IsUsernameAvailable(username string) (
	isUsernameAvailable bool,
	isVerified bool,
	err error,
) {
	var user models.User
	err = u.Conn.DB.Select("username", "verified").Where(&models.User{
		Username: username,
	}).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			if strings.ToLower(user.Username) == strings.ToLower(username) {
				return false, false, nil
			}
			return true, false, nil
		}

		return false, false, err
	}

	return false, user.Verified, nil
}

// Create is a function that is used to create a new user in the relational database
func (u *User) Create(user models.User) (
	newUser models.User,
	err error,
) {
	newUser = user
	err = u.Conn.DB.Create(&newUser).Error
	if err != nil {
		return models.User{}, err
	}

	return newUser, nil
}
