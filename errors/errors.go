// Package errors contians http errors and other custom errors
package errors

import (
	errs "errors"
	"fmt"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

//revive:disable

var (
	ErrInternalServerError                     = fmt.Errorf("internal_server_error")
	ErrUnauthorized                            = fmt.Errorf("unauthorized")
	ErrAccessTokenNotProvided                  = fmt.Errorf("access_token_not_provided")
	ErrBadRequest                              = fmt.Errorf("bad_request")
	ErrIncorrectCredentials                    = fmt.Errorf("incorrect_credentials")
	ErrRefreshTokenExpired                     = fmt.Errorf("refresh_token_expired")
	ErrRefreshTokenNotProvided                 = fmt.Errorf("refresh_token_not_provided")
	ErrAccessTokenExpired                      = fmt.Errorf("access_token_expired")
	ErrUsernameAlreadyUsed                     = fmt.Errorf("username_already_used")
	ErrEmailAlreadyUsed                        = fmt.Errorf("email_already_used")
	ErrEmailConfirmationExpired                = fmt.Errorf("email_confirmation_expired")
	ErrHaveAnAccountWithTheEmail               = fmt.Errorf("already_have_an_account")
	ErrNoAccountWithEmail                      = fmt.Errorf("no_account_with_email")
	ErrNoAccountWithUsername                   = fmt.Errorf("no_account_with_username")
	ErrAddAUsername                            = fmt.Errorf("add_a_username")
	ErrTwoFactorverificationNotEnabled         = fmt.Errorf("two_factor_verification_not_enabled")
	ErrContinueWithTwoFactorAuthentication     = fmt.Errorf("continue_with_two_factor_authentication")
	ErrOTPTokenIsNotValid                      = fmt.Errorf("otp_token_is_not_valid")
	ErrMemonicPhraseIsNotValid                 = fmt.Errorf("memonic_phrase_not_valid")
	ErrReAuthTokenNotPresent                   = fmt.Errorf("reauth_token_not_present")
	ErrVerifyYourEmailAddressFirst             = fmt.Errorf("verify_your_email_address_first")
	ErrTokenExpired                            = fmt.Errorf("token_expired")
	ErrPassKeyCannotBeVerified                 = fmt.Errorf("passkey_cannot_be_verified")
	ErrPassKeyAlreadyCreated                   = fmt.Errorf("passkey_already_created")
	ErrPasskeyWithTheGivenIDIsNotFound         = fmt.Errorf("passkey_with_the_given_id_is_not_found")
	ErrCouldNotParseAccessKeyFromOAuthProvider = fmt.Errorf("could_not_parse_access_token_from_oauth_provider")
	ErrCouldNotGetUserFromOAuthProvider        = fmt.Errorf("could_not_parse_user_from_oauth_provider")
	ErrEnterANewUsername                       = fmt.Errorf("enter_a_new_username")
	ErrLinkAccountWithEmail                    = fmt.Errorf("link_account_with_exsisting_email")
	Okay                                       = "okay"
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
	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "access_token",
		Value:   "",
		Expires: expired,
	})
	return unauthorized(c, ErrAccessTokenExpired)
}

func AccessTokenNotProvided(c *fiber.Ctx) error {
	return unauthorized(c, ErrAccessTokenNotProvided)
}

func RefreshTokenExpired(c *fiber.Ctx) error {
	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "refresh_token",
		Value:   "",
		Expires: expired,
	})
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

func TwoFactorVerificationNotEnabled(c *fiber.Ctx) error {
	return badrequest(c, ErrTwoFactorverificationNotEnabled)
}

func ContinueWithTwoFactorAuthentication(c *fiber.Ctx, user schemas.User) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": ErrContinueWithTwoFactorAuthentication.Error(),
		"user":   user,
	})
}

func OTPTokenIsNotValid(c *fiber.Ctx) error {
	return badrequest(c, ErrOTPTokenIsNotValid)
}

func MemonicPhraseIsNotMatching(c *fiber.Ctx) error {
	return badrequest(c, ErrMemonicPhraseIsNotValid)
}

func ReAuthTokenNotPresent(c *fiber.Ctx) error {
	return badrequest(c, ErrReAuthTokenNotPresent)
}

func VerifyYourEmailAddressFirt(c *fiber.Ctx) error {
	return badrequest(c, ErrVerifyYourEmailAddressFirst)
}

func TokenExpired(c *fiber.Ctx) error {
	return badrequest(c, ErrTokenExpired)
}

func PassKeyCannotBeVerified(c *fiber.Ctx) error {
	return badrequest(c, ErrPassKeyCannotBeVerified)
}

func PassKeyAlreadyCreated(c *fiber.Ctx) error {
	return badrequest(c, ErrPassKeyAlreadyCreated)
}

func PassKeyOfGivenIDNotFound(c *fiber.Ctx) error {
	return badrequest(c, ErrPasskeyWithTheGivenIDIsNotFound)
}

func UseANewUsername(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: ErrAddAUsername.Error(),
	})
}

func LinkAccount(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: ErrLinkAccountWithEmail.Error(),
	})
}

func OAuthStateRedirect(c *fiber.Ctx, env *config.Env, provider string, state error) error {
	if state == nil {
		return c.Redirect(env.FrontendURL)
	}
	return c.Redirect(fmt.Sprintf("%s?state=%s&provider=%s", env.FrontendURL, state, provider))
}

func Done(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: Okay,
	})
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
