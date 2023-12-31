// Package validate contains custom validation functions
package validate

import (
	"net/mail"
	"regexp"

	"github.com/go-playground/validator/v10"
	passwordvalidator "github.com/wagslane/go-password-validator"
)

// Username is a custom validation function that is used to validate the username
func Username(fl validator.FieldLevel) bool {
	regex, err := regexp.Compile(`^[a-zA-Z0-9_.#]{1,20}$`)
	if err != nil {
		return false
	}

	return regex.MatchString(fl.Field().String())
}

// Password is custom validation function that is used to validate passwords
func Password(fl validator.FieldLevel) bool {
	const minEntropy = 60

	err := passwordvalidator.Validate(fl.Field().String(), minEntropy)
	return err == nil
}

// LoginWithEmailOrUsernameAndPassword is a function to login the user with the username and the password or email and the password
func LoginWithEmailOrUsernameAndPassword(fl validator.FieldLevel) bool {
	username := fl.Parent().FieldByName("Username").String()
	email := fl.Parent().FieldByName("Email").String()

	if username == "" && email == "" {
		return false
	}

	if email != "" {
		_, err := mail.ParseAddress(email)
		return err == nil
	}

	regex, err := regexp.Compile(`^[a-zA-Z0-9_.#]{1,20}$`)
	if err != nil {
		return false
	}

	return regex.MatchString(username)
}

// OTP is a function that is used to ensure the that the OTP code is in the proper format
func OTP(fl validator.FieldLevel) bool {
	regex, err := regexp.Compile(`^\d{3}-\d{3}$`)
	if err != nil {
		return false
	}

	return regex.MatchString(fl.Field().String())
}
