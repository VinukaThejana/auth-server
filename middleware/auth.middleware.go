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
)

// Auth contains auth related middlewares
type Auth struct {
	Conn *connect.Connector
	Env  *config.Env
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

	accessTokenS := token.AccessToken{
		Conn: a.Conn,
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

	sessionC := c.Cookies("session")
	if sessionC == "" {
		return errors.Unauthorized(c)
	}

	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
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
	sessionTokenC := c.Cookies("session_token")
	if sessionTokenC == "" {
		return errors.Unauthorized(c)
	}

	refreshTokenS := token.RefreshToken{
		Conn: a.Conn,
		Env:  a.Env,
	}
	sessionTokenS := token.SessionToken{
		Conn: a.Conn,
		Env:  a.Env,
	}

	isValid, err := refreshTokenS.Validate(refreshTokenC)
	token, err := sessionTokenS.Validate(sessionTokenC)
	if err != nil {
		if ok := (errors.CheckTokenError{}.Expired(err)); ok {
			return errors.Unauthorized(c)
		}
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if !isValid {
		return errors.Unauthorized(c)
	}

	user, err := sessionTokenS.GetUserDetails(token)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	session.SaveRefreshToken(c, refreshTokenC)
	session.SaveSessionToken(c, sessionTokenC)
	session.Add(c, user)

	return c.Next()
}
