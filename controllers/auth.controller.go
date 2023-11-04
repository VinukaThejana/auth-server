package controllers

import (
	"fmt"
	"strings"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/services"
	"github.com/VinukaThejana/auth/session"
	"github.com/VinukaThejana/auth/token"
	"github.com/VinukaThejana/auth/utils"
	"github.com/VinukaThejana/auth/validate"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Auth struct contains all the auth related controllers
type Auth struct {
	Conn *connect.Connector
	Env  *config.Env
}

// RegisterWEmailAndPassword is a function that is used to register users to the platfrom with email and password login method
func (a *Auth) RegisterWEmailAndPassword(c *fiber.Ctx) error {
	var payload struct {
		Name     string `json:"name" validate:"required,min=3,max=60"`
		Username string `json:"username" validate:"required,min=3,max=20,validate_username"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8,max=200,validate_password"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_username", validate.Username)
	v.RegisterValidation("validate_password", validate.Password)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	newUserD := models.User{
		Name:     payload.Name,
		Username: payload.Username,
		Email:    payload.Email,
		PhotoURL: fmt.Sprintf("https://api.dicebear.com/7.x/bottts/svg?seed=%s", payload.Username),
		Password: string(hashedPassword),
	}

	userS := services.User{
		Conn: a.Conn,
	}
	newUser, err := userS.Create(newUserD)
	if err != nil {
		if ok := (errors.CheckDBError{}.DuplicateKey(err)); ok {
			logger.Log(fmt.Sprintf("New user details : %+v", newUser))
			if strings.Contains(err.Error(), "idx_users_email") {
				user, err := userS.GetUserWithEmail(payload.Email)
				if err != nil {
					logger.Error(err)
					return errors.EmailAlreadyUsed(c)
				}

				if user.Verified {
					return errors.EmailAlreadyUsed(c)
				}

				err = userS.DeleteUser(*user)
				if err != nil {
					logger.Error(err)
					return errors.EmailAlreadyUsed(c)
				}
			} else if strings.Contains(err.Error(), "idx_users_username") {
				user, err := userS.GetUserWithUsername(payload.Username)
				if err != nil {
					logger.Error(err)
					return errors.UsernameAlreadyUsed(c)
				}

				if user.Verified {
					return errors.UsernameAlreadyUsed(c)
				}

				err = userS.DeleteUser(*user)
				if err != nil {
					logger.Error(err)
					return errors.UsernameAlreadyUsed(c)
				}
			} else {
				return errors.BadRequest(c)
			}

			newUser, err = userS.Create(newUserD)
			if err != nil {
				logger.Error(err)
				return errors.InternalServerErr(c)
			}
		} else {
			logger.Error(err)
			return errors.InternalServerErr(c)
		}
	}

	emailClient := utils.Email{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: *newUser.ID,
	}

	emailClient.SendConfirmation(newUser.Email)

	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: errors.Okay,
	})
}

// LoginWEmailAndPassword is a funciton that is used to login the user with the email and password
func (a *Auth) LoginWEmailAndPassword(c *fiber.Ctx) error {
	var payload struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password" validate:"required,min=8,max=200,validate_password"`
		Validate string `validate:"validate_login"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_password", validate.Password)
	v.RegisterValidation("validate_login", validate.LoginWithEmailOrUsernameAndPassword)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userS := services.User{
		Conn: a.Conn,
	}

	var user *models.User
	var custom error

	if payload.Email != "" {
		user, err = userS.GetUserWithEmail(payload.Email)
		custom = errors.NoAccountWithEmail(c)
	} else {
		user, err = userS.GetUserWithUsername(payload.Username)
		custom = errors.NoAccountWithUsername(c)
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return custom
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		logger.Error(err)
		return errors.InCorrectCredentials(c)
	}

	refreshTokenS := token.RefreshToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: *user.ID,
	}
	accessTokenS := token.AccessToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: *user.ID,
	}
	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
		Env:  a.Env,
	}

	refreshTokenD, err := refreshTokenS.Create(schemas.RefreshTokenMetadata{})
	if err != nil {
		logger.ErrorWithMsg(err, "Failed to create the refresh token")
		return errors.InternalServerErr(c)
	}
	accessTokenD, err := accessTokenS.Create(refreshTokenD.TokenUUID)
	if err != nil {
		logger.ErrorWithMsg(err, "Failed to create the access token")
		return errors.InternalServerErr(c)
	}
	sessionTokenD, err := sessionTokenS.Create(*user)
	if err != nil {
		logger.ErrorWithMsg(err, "Failed to create the session token")
		return errors.InternalServerErr(c)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    *accessTokenD.Token,
		Path:     "/",
		MaxAge:   a.Env.AccessTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenD.Token,
		Path:     "/",
		MaxAge:   a.Env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "session",
		Value:    *sessionTokenD.Token,
		Path:     "/",
		MaxAge:   a.Env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": errors.Okay,
		"user":   schemas.FilterUser(*user),
	})
}

// RefreshAccessToken is a function that is used to refresh the access token with the refresh token
func (a *Auth) RefreshAccessToken(c *fiber.Ctx) error {
	refreshTokenC := session.GetRefreshToken(c)
	user := session.Get(c)

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	refreshTokenS := token.RefreshToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: userID,
	}

	refreshToken, err := refreshTokenS.Get(refreshTokenC)
	if err != nil {
		if err == errors.ErrRefreshTokenExpired {
			return errors.RefreshTokenExpired(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	accessTokenS := token.AccessToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: userID,
	}

	tokenDetails, err := accessTokenS.Create(refreshToken.TokenUUID)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    *tokenDetails.Token,
		Path:     "/",
		MaxAge:   a.Env.AccessTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: errors.Okay,
	})
}

// CreateTOTP is a function that is used to create the user OTP
func (a *Auth) CreateTOTP(c *fiber.Ctx) error {
	user := session.Get(c)

	userS := services.User{
		Conn: a.Conn,
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "auth",
		AccountName: user.ID,
		SecretSize:  15,
	})
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	memonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = userS.SetupTOTP2FactorVerification(models.OTP{
		UserID:        &userID,
		Secret:        key.Secret(),
		AuthURL:       key.URL(),
		MemonicPhrase: memonic,
	})
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": errors.Okay,
		"secret": key.Secret(),
		"url":    key.URL(),
	})
}

func reauthenticate(c *fiber.Ctx, a *Auth, userID string) error {
	reAuthTokenS := token.AuthConfirmToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: userID,
	}

	tokenDetails, err := reAuthTokenS.Create()
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "reauth_token",
		Value:    *tokenDetails.Token,
		Path:     "/",
		MaxAge:   5 * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: errors.Okay,
	})
}

// ReAuthenticatWithEmailAndPassword is a function that is used to reauthenticat the user with email and password
func (a *Auth) ReAuthenticatWithEmailAndPassword(c *fiber.Ctx) error {
	var payload struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password" validate:"required,min=8,max=200,validate_password"`
		Validate string `validate:"validate_login"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_password", validate.Password)
	v.RegisterValidation("validate_login", validate.LoginWithEmailOrUsernameAndPassword)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userS := services.User{
		Conn: a.Conn,
	}

	var user *models.User
	var custom error

	if payload.Email != "" {
		user, err = userS.GetUserWithEmail(payload.Email)
		custom = errors.NoAccountWithEmail(c)
	} else {
		user, err = userS.GetUserWithUsername(payload.Username)
		custom = errors.NoAccountWithUsername(c)
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return custom
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		logger.Error(err)
		return errors.InCorrectCredentials(c)
	}

	return reauthenticate(c, a, user.ID.String())
}

// VerifyTOTP is a function that is used to verify the TOTP token
func (a *Auth) VerifyTOTP(c *fiber.Ctx) error {
	user := session.Get(c)
	userID, err := uuid.Parse(user.ID)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var payload struct {
		Code string `json:"code" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err = v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	var otp models.OTP
	err = a.Conn.DB.Where(&models.OTP{
		UserID: &userID,
	}).First(&otp).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.TwoFactorVerificationNotEnabled(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	valid := totp.Validate(payload.Code, otp.Secret)
	if !valid {
		return errors.OTPTokenIsNotValid(c)
	}

	if !otp.Verified {
		otp.Verified = true
		err = a.Conn.DB.Save(&otp).Error
		if err != nil {
			logger.Error(err)
			errors.InternalServerErr(c)
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":         errors.Okay,
		"memonic_phrase": otp.MemonicPhrase,
	})
}

// ResetTwoFactorAuthentication is a function that is used to verify the two factor authentication by using the memonic phrase
func (a *Auth) ResetTwoFactorAuthentication(c *fiber.Ctx) error {
	var payload struct {
		Username      string `json:"username" validate:"required,min=3,max=20,validate_username"`
		Password      string `json:"password" validate:"required,min=8,max=200,validate_password"`
		MemonicPhrase string `json:"memonic_phrase" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_username", validate.Username)
	v.RegisterValidation("validate_password", validate.Password)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	var user models.User
	err = a.Conn.DB.Where(&models.User{
		Username: payload.Username,
	}).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.InCorrectCredentials(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		logger.Error(err)
		return errors.InCorrectCredentials(c)
	}

	var otp models.OTP
	err = a.Conn.DB.Where(&models.OTP{
		UserID: user.ID,
	}).First(&otp).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.TwoFactorVerificationNotEnabled(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if payload.MemonicPhrase != otp.MemonicPhrase {
		return errors.MemonicPhraseIsNotMatching(c)
	}

	err = a.Conn.DB.Delete(&otp).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: errors.Okay,
	})
}
