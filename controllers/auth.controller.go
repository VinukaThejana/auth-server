package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
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

	emailClient := services.Email{
		Conn: a.Conn,
		Env:  a.Env,
	}

	err = emailClient.SendConfirmation(*newUser.ID, newUser.Email)
	if err != nil {
		logger.Error(err)
	}

	return errors.Done(c)
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
		if strings.HasPrefix(err.Error(), "Key: 'Password'") {
			return errors.InCorrectCredentials(c)
		}

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

	if user.TwoFactorEnabled {
		return errors.ContinueWithTwoFactorAuthentication(c, schemas.FilterUser(*user))
	}

	err = utils.GenerateCookies(c, user, a.Conn, a.Env)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": errors.Okay,
		"user":   schemas.FilterUser(*user),
	})
}

// RefreshAccessToken is a function that is used to refresh the access token with the refresh token
func (a *Auth) RefreshAccessToken(c *fiber.Ctx) error {
	refreshTokenC := session.GetRefreshToken(c)
	user := session.Get(c)

	refreshTokenS := token.RefreshToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: *user.ID,
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
		UserID: *user.ID,
	}

	tokenDetails, err := accessTokenS.Create(refreshToken.TokenUUID)
	if err != nil {
		if err == errors.ErrRefreshTokenExpired {
			tokenS := services.Token{
				Conn: a.Conn,
			}

			tokenS.DeleteCookies(c)
			return errors.RefreshTokenExpired(c)
		}

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

	return errors.Done(c)
}

// Logout is a function that is used to logout a user by clearing the access_token, refresh_token and the session token
func (a *Auth) Logout(c *fiber.Ctx) error {
	refreshTokenC := session.GetRefreshToken(c)
	user := session.Get(c)

	refreshTokenS := token.RefreshToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: *user.ID,
	}

	refreshToken, err := refreshTokenS.Get(refreshTokenC)
	if err != nil {
		if err == errors.ErrRefreshTokenExpired {
			return errors.RefreshTokenExpired(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	tokenUUID, err := uuid.Parse(refreshToken.TokenUUID)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	tokenS := services.Token{
		Conn: a.Conn,
	}

	tokenS.DeleteCookies(c)
	err = tokenS.DeleteTokenData(*user.ID, tokenUUID)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = a.Conn.M.RemoveObject(
		context.Background(),
		"sessions",
		fmt.Sprintf("%s/%s", user.ID.String(), tokenUUID.String()),
		minio.RemoveObjectOptions{
			GovernanceBypass: true,
		},
	)
	if err != nil {
		logger.Error(err)
	}

	return errors.Done(c)
}

// CreateTOTP is a function that is used to create the user OTP
func (a *Auth) CreateTOTP(c *fiber.Ctx) error {
	user := session.Get(c)

	userS := services.User{
		Conn: a.Conn,
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "auth",
		AccountName: user.ID.String(),
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

	err = userS.SetupTOTP2FactorVerification(models.OTP{
		UserID:        user.ID,
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

	return errors.Done(c)
}

// ReAuthenticateWithPassword is a function that is used to reauthenticate the user with email and password
func (a *Auth) ReAuthenticateWithPassword(c *fiber.Ctx) error {
	user := session.Get(c)

	var payload struct {
		Password string `json:"password" validate:"required,min=8,max=200,validate_password"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_password", validate.Password)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userS := services.User{
		Conn: a.Conn,
	}

	userM, err := userS.GetUserWithID(*user.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.BadRequest(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = bcrypt.CompareHashAndPassword([]byte(userM.Password), []byte(payload.Password))
	if err != nil {
		logger.Error(err)
		return errors.InCorrectCredentials(c)
	}

	return reauthenticate(c, a, user.ID.String())
}

// ReAuthenticateWithPassKey is a function that is used to reauthenticate with the users passkey
func (a *Auth) ReAuthenticateWithPassKey(c *fiber.Ctx) error {
	usera := session.Get(c)

	var payload struct {
		Cred schemas.PassKeyCredWhenLogginIn `json:"cred" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userID, err := uuid.Parse(payload.Cred.Response.UserHandle)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if userID != *usera.ID {
		return errors.BadRequest(c)
	}

	clientDataBytes, err := base64url.Decode(payload.Cred.Response.ClientDataJSON)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var clientData schemas.PasskeysClientData
	err = json.Unmarshal(clientDataBytes, &clientData)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	val := a.Conn.R.Challenge.Get(context.Background(), clientData.Challenge).Val()
	if val == "" {
		return errors.PassKeyCannotBeVerified(c)
	}

	cred := schemas.PassKeyCredWhenLogginIn{
		ID:                      payload.Cred.ID,
		RawID:                   payload.Cred.RawID,
		Type:                    payload.Cred.Type,
		ClientExtensionResults:  payload.Cred.ClientExtensionResults,
		AuthenticatorAttachment: payload.Cred.AuthenticatorAttachment,
		Response: struct {
			AuthenticatorData string "json:\"authenticatorData\" validate:\"required\""
			ClientDataJSON    string "json:\"clientDataJSON\" validate:\"required\""
			Signature         string "json:\"signature\" validate:\"required\""
			UserHandle        string "json:\"userHandle\" validate:\"required\""
		}{
			AuthenticatorData: payload.Cred.Response.AuthenticatorData,
			ClientDataJSON:    payload.Cred.Response.ClientDataJSON,
			Signature:         payload.Cred.Response.Signature,
			UserHandle:        payload.Cred.Response.UserHandle,
		},
	}

	credStr, err := json.Marshal(cred)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var passKey models.PassKeys
	err = a.Conn.DB.Where(&models.PassKeys{
		UserID:    &userID,
		PassKeyID: cred.ID,
	}).First(&passKey).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.PassKeyOfGivenIDNotFound(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	passKeyStr, err := json.Marshal(passKey)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/webauthn/validate", a.Env.FrontendURL), bytes.NewBuffer([]byte(
		fmt.Sprintf(`{"challenge":"%s","cred":%s, "passKey": %s }`, clientData.Challenge, credStr, passKeyStr),
	)))
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	defer resp.Body.Close()

	var body struct {
		NewCounter *int         `json:"newCounter"`
		Err        *interface{} `json:"err"`
		IsValid    bool         `json:"isValid"`
	}

	bodyC, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = json.Unmarshal(bodyC, &body)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if resp.StatusCode != http.StatusOK {
		if body.Err != nil {
			logger.Error(fmt.Errorf(fmt.Sprint(*body.Err)))
		}
		return errors.InternalServerErr(c)
	}

	if !body.IsValid || body.NewCounter == nil {
		return errors.PassKeyCannotBeVerified(c)
	}

	passKey.Count = *body.NewCounter

	err = a.Conn.DB.Save(passKey).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	userS := services.User{
		Conn: a.Conn,
	}

	userM, err := userS.GetUserWithID(userID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.BadRequest(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return reauthenticate(c, a, userM.ID.String())
}

// VerifyTOTP is a function that is used to verify the TOTP token
func (a *Auth) VerifyTOTP(c *fiber.Ctx) error {
	user := session.Get(c)

	var payload struct {
		Code string `json:"code" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
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

	valid := totp.Validate(payload.Code, otp.Secret)
	if !valid {
		return errors.OTPTokenIsNotValid(c)
	}

	otp.Verified = true

	err = a.Conn.DB.Save(&otp).Error
	if err != nil {
		logger.Error(err)
		errors.InternalServerErr(c)
	}

	userS := services.User{
		Conn: a.Conn,
	}

	userM, err := userS.GetUserWithID(*user.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Unauthorized(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	if userM == nil {
		return errors.BadRequest(c)
	}

	userM.TwoFactorEnabled = true
	err = a.Conn.DB.Save(&userM).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
		Env:  a.Env,
	}

	sessionTokenD, err := sessionTokenS.Create(*userM)
	if err != nil {
		logger.ErrorWithMsg(err, "Failed to create the session token")
		return errors.InternalServerErr(c)
	}

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
		"status":         errors.Okay,
		"memonic_phrase": otp.MemonicPhrase,
	})
}

// ValidateTOTPToken is a function that is used to login 2 factor enabled users
func (a *Auth) ValidateTOTPToken(c *fiber.Ctx) error {
	var payload struct {
		ID   string `json:"id" validate:"required,uuid"`
		Code string `json:"code" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userID, err := uuid.Parse(payload.ID)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userS := services.User{
		Conn: a.Conn,
	}

	user, err := userS.GetUserWithID(userID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.BadRequest(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	if user == nil {
		return errors.BadRequest(c)
	}

	if !user.TwoFactorEnabled {
		return errors.TwoFactorVerificationNotEnabled(c)
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

	err = utils.GenerateCookies(c, user, a.Conn, a.Env)
	if err != nil {
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": errors.Okay,
		"user":   schemas.FilterUser(*user),
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

	user.TwoFactorEnabled = false
	err = a.Conn.DB.Save(user).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = a.Conn.DB.Delete(&otp).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
		Env:  a.Env,
	}

	sessionTokenD, err := sessionTokenS.Create(user)
	if err != nil {
		logger.ErrorWithMsg(err, "Failed to create the session token")
		return errors.InternalServerErr(c)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "session",
		Value:    *sessionTokenD.Token,
		Path:     "/",
		MaxAge:   a.Env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return errors.Done(c)
}

// GetChallenge is a function that is used to get a crypographic challenge
func (a *Auth) GetChallenge(c *fiber.Ctx) error {
	challenge, err := utils.GenerateChallenge()
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = a.Conn.R.Challenge.SetEx(context.Background(), *challenge, false, time.Second*120).Err()
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":    errors.Okay,
		"challenge": *challenge,
	})
}

// CreatePassKey is a function that is used to create a PassKey
func (a *Auth) CreatePassKey(c *fiber.Ctx) error {
	user := session.Get(c)

	var payload struct {
		Name string                          `json:"name" validate:"required,min=3,max=100"`
		Cred schemas.PassKeyCredWhenCreating `json:"cred" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	clientDataBytes, err := base64url.Decode(payload.Cred.Response.ClientDataJSON)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var clientData schemas.PasskeysClientData
	err = json.Unmarshal(clientDataBytes, &clientData)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	val := a.Conn.R.Challenge.Get(context.Background(), clientData.Challenge).Val()
	if val == "" {
		return errors.PassKeyCannotBeVerified(c)
	}

	cred := schemas.PassKeyCredWhenCreating{
		ID:    payload.Cred.ID,
		RawID: payload.Cred.RawID,
		Type:  payload.Cred.Type,
		Response: struct {
			AttestationObject string        "json:\"attestationObject\" validate:\"required\""
			ClientDataJSON    string        "json:\"clientDataJSON\" validate:\"required\""
			Transports        []interface{} "json:\"transports\""
		}{
			ClientDataJSON:    payload.Cred.Response.ClientDataJSON,
			Transports:        payload.Cred.Response.Transports,
			AttestationObject: payload.Cred.Response.AttestationObject,
		},
	}
	credStr, err := json.Marshal(cred)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/webauthn/register", a.Env.FrontendURL), bytes.NewBuffer([]byte(
		fmt.Sprintf(`{"challenge":"%s","cred":%s }`, clientData.Challenge, credStr),
	)))
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	defer resp.Body.Close()

	var body struct {
		CredentialID        *string      `json:"credentialID"`
		CredentialPublicKey *string      `json:"credentialPublicKey"`
		Err                 *interface{} `json:"err"`
		IsValid             bool         `json:"isValid"`
	}

	bodyC, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = json.Unmarshal(bodyC, &body)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.InternalServerErr(c)
	}

	if body.CredentialID == nil || body.CredentialPublicKey == nil || !body.IsValid {
		return errors.PassKeyCannotBeVerified(c)
	}

	passKey := models.PassKeys{
		Name:      payload.Name,
		UserID:    user.ID,
		PassKeyID: *body.CredentialID,
		PublicKey: *body.CredentialPublicKey,
		Count:     0,
	}

	err = a.Conn.DB.Create(passKey).Error
	if err != nil {
		if ok := (errors.CheckDBError{}.DuplicateKey(err)); ok {
			return errors.PassKeyAlreadyCreated(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return errors.Done(c)
}

// LoginWithPassKey is a function that is used to login with the PassKey
func (a *Auth) LoginWithPassKey(c *fiber.Ctx) error {
	var payload struct {
		Cred schemas.PassKeyCredWhenLogginIn `json:"cred" validate:"required"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	userID, err := uuid.Parse(payload.Cred.Response.UserHandle)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	clientDataBytes, err := base64url.Decode(payload.Cred.Response.ClientDataJSON)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var clientData schemas.PasskeysClientData
	err = json.Unmarshal(clientDataBytes, &clientData)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	val := a.Conn.R.Challenge.Get(context.Background(), clientData.Challenge).Val()
	if val == "" {
		return errors.PassKeyCannotBeVerified(c)
	}

	cred := schemas.PassKeyCredWhenLogginIn{
		ID:                      payload.Cred.ID,
		RawID:                   payload.Cred.RawID,
		Type:                    payload.Cred.Type,
		ClientExtensionResults:  payload.Cred.ClientExtensionResults,
		AuthenticatorAttachment: payload.Cred.AuthenticatorAttachment,
		Response: struct {
			AuthenticatorData string "json:\"authenticatorData\" validate:\"required\""
			ClientDataJSON    string "json:\"clientDataJSON\" validate:\"required\""
			Signature         string "json:\"signature\" validate:\"required\""
			UserHandle        string "json:\"userHandle\" validate:\"required\""
		}{
			AuthenticatorData: payload.Cred.Response.AuthenticatorData,
			ClientDataJSON:    payload.Cred.Response.ClientDataJSON,
			Signature:         payload.Cred.Response.Signature,
			UserHandle:        payload.Cred.Response.UserHandle,
		},
	}

	credStr, err := json.Marshal(cred)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var passKey models.PassKeys
	err = a.Conn.DB.Where(&models.PassKeys{
		UserID:    &userID,
		PassKeyID: cred.ID,
	}).First(&passKey).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.PassKeyOfGivenIDNotFound(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	passKeyStr, err := json.Marshal(passKey)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/webauthn/validate", a.Env.FrontendURL), bytes.NewBuffer([]byte(
		fmt.Sprintf(`{"challenge":"%s","cred":%s, "passKey": %s }`, clientData.Challenge, credStr, passKeyStr),
	)))
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}
	defer resp.Body.Close()

	var body struct {
		NewCounter *int         `json:"newCounter"`
		Err        *interface{} `json:"err"`
		IsValid    bool         `json:"isValid"`
	}

	bodyC, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = json.Unmarshal(bodyC, &body)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if resp.StatusCode != http.StatusOK {
		if body.Err != nil {
			logger.Error(fmt.Errorf(fmt.Sprint(*body.Err)))
		}
		return errors.InternalServerErr(c)
	}

	if !body.IsValid || body.NewCounter == nil {
		return errors.PassKeyCannotBeVerified(c)
	}

	passKey.Count = *body.NewCounter

	err = a.Conn.DB.Save(passKey).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	var user models.User
	err = a.Conn.DB.Where(&models.User{
		ID: &userID,
	}).First(&user).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = utils.GenerateCookies(c, &user, a.Conn, a.Env)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": errors.Okay,
		"user":   schemas.FilterUser(user),
	})
}

// GetPassKeys is a function that is used to GetPasskey relevant to user
func (a *Auth) GetPassKeys(c *fiber.Ctx) error {
	type res struct {
		Status   string            `json:"status"`
		PassKeys []models.PassKeys `json:"passKeys"`
	}

	user := session.Get(c)

	var passKeys []models.PassKeys
	err := a.Conn.DB.Where(&models.PassKeys{
		UserID: user.ID,
	}).Find(&passKeys).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusOK).JSON(res{
				Status:   errors.Okay,
				PassKeys: []models.PassKeys{},
			})
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(res{
		Status:   errors.Okay,
		PassKeys: passKeys,
	})
}

// EditPassKey is a function that is used to change a passkey name
func (a *Auth) EditPassKey(c *fiber.Ctx) error {
	user := session.Get(c)

	var payload struct {
		PassKeyID string `json:"passKeyID" validate:"required,min=2"`
		NewName   string `json:"newName" validate:"required,min=3,max=200"`
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		return errors.BadRequest(c)
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = a.Conn.DB.Model(&models.PassKeys{}).Where(&models.PassKeys{
		UserID:    user.ID,
		PassKeyID: payload.PassKeyID,
	}).Update("name", payload.NewName).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.PassKeyOfGivenIDNotFound(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return errors.Done(c)
}

// DeletePassKey is a function that is used to delete a passkey
func (a *Auth) DeletePassKey(c *fiber.Ctx) error {
	user := session.Get(c)

	var payload struct {
		PassKeyID string `json:"passKeyID" validate:"required,min=2"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	err := v.Struct(payload)
	if err != nil {
		return errors.BadRequest(c)
	}

	err = a.Conn.DB.Delete(&models.PassKeys{
		PassKeyID: payload.PassKeyID,
		UserID:    user.ID,
	}).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.PassKeyOfGivenIDNotFound(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return errors.Done(c)
}
