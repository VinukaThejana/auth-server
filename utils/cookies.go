package utils

import (
	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/session"
	"github.com/VinukaThejana/auth/token"
	"github.com/gofiber/fiber/v2"
)

// GenerateCookies is a function that is used to generate cookies that are used to login the user
func GenerateCookies(c *fiber.Ctx, user *models.User, conn *connect.Connector, env *config.Env) error {
	refreshTokenS := token.RefreshToken{
		Conn:   conn,
		Env:    env,
		UserID: *user.ID,
	}
	accessTokenS := token.AccessToken{
		Conn:   conn,
		Env:    env,
		UserID: *user.ID,
	}
	sessionTokenS := token.SessionToken{
		Conn: conn,
		Env:  env,
	}

	ua := session.GetUA(c)

	refreshTokenD, err := refreshTokenS.Create(schemas.RefreshTokenMetadata{
		IPAddress:    c.IP(),
		DeviceVendor: ua.Device.Vendor,
		DeviceModel:  ua.Device.Model,
		OSName:       ua.OS.Name,
		OSVersion:    ua.OS.Version,
	})
	if err != nil {
		return err
	}
	accessTokenD, err := accessTokenS.Create(refreshTokenD.TokenUUID)
	if err != nil {
		return err
	}
	sessionTokenD, err := sessionTokenS.Create(*user)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    *accessTokenD.Token,
		Path:     "/",
		MaxAge:   env.AccessTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenD.Token,
		Path:     "/",
		MaxAge:   env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "session",
		Value:    *sessionTokenD.Token,
		Path:     "/",
		MaxAge:   env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return nil
}

// GenerateOAuthCookie is a function that is used to generate oauth token to manage oauth related activites
func GenerateOAuthCookie(c *fiber.Ctx, conn *connect.Connector, env *config.Env, provider string, accessToken string) error {
	oauthTokenS := token.OAuthToken{
		Conn:        conn,
		Env:         env,
		Provider:    provider,
		AccessToken: accessToken,
	}

	tokenDetails, err := oauthTokenS.Create()
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     "oauth_token",
		Value:    *tokenDetails.Token,
		Path:     "/",
		MaxAge:   env.AccessTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return nil
}
