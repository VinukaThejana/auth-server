package middleware

import (
	"strings"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/session"
	"github.com/VinukaThejana/auth/token"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Auth contains auth related middlewares
type Auth struct {
	Conn *connect.Connector
	Env  *config.Env
}

// CheckAdmin is a function that is used to check wether the user is a Admin user
func (a *Auth) CheckAdmin(c *fiber.Ctx) error {
	var adminToken string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer ") {
		adminToken = strings.TrimPrefix(authorization, "Bearer ")
	} else {
		return errors.Unauthorized(c)
	}

	if adminToken != a.Env.AdminSecret {
		return errors.Unauthorized(c)
	}

	return c.Next()
}

// Check is a function that is used to check wether the user is authenticated
func (a *Auth) Check(c *fiber.Ctx) error {
	var accessToken string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer ") {
		accessToken = strings.TrimPrefix(authorization, "Bearer ")
	} else if c.Cookies("access_token") != "" {
		accessToken = c.Cookies("access_token")
	} else {
		return errors.AccessTokenNotProvided(c)
	}

	sessionC := c.Cookies("session")
	if sessionC == "" {
		return errors.Unauthorized(c)
	}

	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
		Env:  a.Env,
	}

	sessionToken, err := sessionTokenS.Validate(sessionC)
	if err != nil {
		if isExpired := (errors.CheckTokenError{}.Expired(err)); isExpired {
			return errors.Unauthorized(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	user, err := sessionTokenS.GetUserDetails(sessionToken)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		logger.Error(err)
		errors.InternalServerErr(c)
	}

	accessTokenS := token.AccessToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: userID,
	}

	isValid, err := accessTokenS.Validate(accessToken)
	if !isValid {
		return errors.AccessTokenExpired(c)
	}
	if err != nil {
		if isExpired := (errors.CheckTokenError{}.Expired(err)); isExpired {
			return errors.AccessTokenExpired(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	session.Add(c, user)
	session.SaveAccessToken(c, accessToken)
	session.SaveSessionToken(c, sessionC)

	return c.Next()
}

// CheckRefreshToken is a used to check ther refresh token
func (a *Auth) CheckRefreshToken(c *fiber.Ctx) error {
	refreshTokenC := c.Cookies("refresh_token")
	if refreshTokenC == "" {
		return errors.Unauthorized(c)
	}
	sessionTokenC := c.Cookies("session")
	if sessionTokenC == "" {
		return errors.Unauthorized(c)
	}

	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
		Env:  a.Env,
	}
	sessionToken, err := sessionTokenS.Validate(sessionTokenC)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	user, err := sessionTokenS.GetUserDetails(sessionToken)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

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

	isValid, err := refreshTokenS.Validate(refreshTokenC)
	if err != nil {
		if ok := (errors.CheckTokenError{}.Expired(err)); ok {
			return errors.Unauthorized(c)
		}

		if err == errors.ErrRefreshTokenExpired {
			return errors.RefreshTokenExpired(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if !isValid {
		return errors.Unauthorized(c)
	}

	session.SaveRefreshToken(c, refreshTokenC)
	session.SaveSessionToken(c, sessionTokenC)
	session.Add(c, user)

	return c.Next()
}

// CheckReAuthToken is a function that is used to check the reauthentication token is present
func (a *Auth) CheckReAuthToken(c *fiber.Ctx) error {
	user := session.Get(c)

	reAuthToken := c.Cookies("reauth_token")
	if reAuthToken == "" {
		return errors.ReAuthTokenNotPresent(c)
	}

	reAuthTokenS := token.AuthConfirmToken{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: user.ID,
	}

	_, err := reAuthTokenS.Validate(reAuthToken)
	if err != nil {
		logger.Error(err)
		return errors.ReAuthTokenNotPresent(c)
	}

	return c.Next()
}
