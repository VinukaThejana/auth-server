// Package errors contians http errors and other custom errors
package errors

import (
	errs "errors"
	"fmt"

	"github.com/VinukaThejana/auth/schemas"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

//revive:disable

var (
	ErrInternalServerError       = fmt.Errorf("internal_server_error")
	ErrUnauthorized              = fmt.Errorf("unauthorized")
	ErrAccessTokenNotProvided    = fmt.Errorf("access_token_not_provided")
	ErrBadRequest                = fmt.Errorf("bad_request")
	ErrIncorrectCredentials      = fmt.Errorf("incorrect_credentials")
	ErrRefreshTokenExpired       = fmt.Errorf("refresh_token_expired")
	ErrRefreshTokenNotProvided   = fmt.Errorf("refresh_token_not_provided")
	ErrAccessTokenExpired        = fmt.Errorf("access_token_expired")
	ErrUsernameAlreadyUsed       = fmt.Errorf("username_already_used")
	ErrEmailAlreadyUsed          = fmt.Errorf("email_already_used")
	ErrEmailConfirmationExpired  = fmt.Errorf("email_confirmation_expired")
	ErrHaveAnAccountWithTheEmail = fmt.Errorf("already_have_an_account")
	ErrNoAccountWithEmail        = fmt.Errorf("no_account_with_email")
	ErrNoAccountWithUsername     = fmt.Errorf("no_account_with_username")
	ErrAddAUsername              = fmt.Errorf("add_a_username")
	Okay                         = "okay"
)

type res schemas.Res

func InternalServerErr(c *fiber.Ctx) error {
	return c.Status(fiber.StatusInternalServerError).JSON(res{
		Status: ErrInternalServerError.Error(),
	})
}

func unauthorized(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusUnauthorized).JSON(res{
		Status: err.Error(),
	})
}

func Unauthorized(c *fiber.Ctx) error {
	return unauthorized(c, ErrUnauthorized)
}

func AccessTokenExpired(c *fiber.Ctx) error {
	return unauthorized(c, ErrAccessTokenExpired)
}

func AccessTokenNotProvided(c *fiber.Ctx) error {
	return unauthorized(c, ErrAccessTokenNotProvided)
}

func RefreshTokenExpired(c *fiber.Ctx) error {
	return unauthorized(c, ErrRefreshTokenExpired)
}

func RefreshTokenNotProvided(c *fiber.Ctx) error {
	return unauthorized(c, ErrRefreshTokenNotProvided)
}

func InCorrectCredentials(c *fiber.Ctx) error {
	return unauthorized(c, ErrIncorrectCredentials)
}

func badrequest(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusBadRequest).JSON(res{
		Status: err.Error(),
	})
}

func BadRequest(c *fiber.Ctx) error {
	return badrequest(c, ErrBadRequest)
}

func UsernameAlreadyUsed(c *fiber.Ctx) error {
	return badrequest(c, ErrUsernameAlreadyUsed)
}

func EmailAlreadyUsed(c *fiber.Ctx) error {
	return badrequest(c, ErrEmailAlreadyUsed)
}

func NoAccountWithEmail(c *fiber.Ctx) error {
	return badrequest(c, ErrNoAccountWithEmail)
}

func NoAccountWithUsername(c *fiber.Ctx) error {
	return badrequest(c, ErrNoAccountWithUsername)
}

//revive:enable

// CheckDBError is a struc that is used to identify the database errors
type CheckDBError struct{}

// DuplicateKey is a function that is used to find wether the the returned postgres error
// is due to a duplicate key entry (A unique key constraint)
func (CheckDBError) DuplicateKey(err error) bool {
	var pgErr *pgconn.PgError
	if errs.As(err, &pgErr) {
		if pgErr.Code == "23505" {
			return true
		}
	}

	return false
}

// CheckTokenError is a struct that is used to handle token related errors
type CheckTokenError struct{}

// Expired is a function that is used to identify wether the token is expired or not
func (CheckTokenError) Expired(err error) bool {
	return err.Error() == "token has invalid claims: token is expired"
}
