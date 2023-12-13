package controllers

import (
	"fmt"
	"net/url"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/enums"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/services"
	"github.com/VinukaThejana/auth/token"
	"github.com/VinukaThejana/auth/utils"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// OAuth is a struct that contains OAuth related controllers
type OAuth struct {
	Conn *connect.Connector
	Env  *config.Env
}

// RedirectToGitHubOAuthFlow is a function that is used to redirect the user to the GitHub oauth flow
func (o *OAuth) RedirectToGitHubOAuthFlow(c *fiber.Ctx) error {
	state := c.Query("state")

	options := url.Values{
		"client_id":    []string{o.Env.GitHubClientID},
		"redirect_uri": []string{o.Env.GitHubRedirectURL},
		"scope":        []string{"user:email"},
		"state":        []string{state},
	}

	githubRedirectURL := fmt.Sprintf("%s?%s", o.Env.GitHubRootURL, options.Encode())
	return c.Redirect(githubRedirectURL)
}

// GitHubCallback is the callback handler that GitHub responds to
func (o *OAuth) GitHubCallback(c *fiber.Ctx) error {
	code := c.Query("code")

	if code == "" {
		return errors.Unauthorized(c)
	}

	oauthS := services.OAuth{
		Conn: o.Conn,
		Env:  o.Env,
	}
	userS := services.User{
		Conn: o.Conn,
	}

	accessToken, err := oauthS.GetGitHubAccessToken(code)
	if err != nil {
		logger.Error(err)
		if err == errors.ErrCouldNotParseAccessKeyFromOAuthProvider {
			err = errors.ErrCouldNotParseAccessKeyFromOAuthProvider
		} else {
			logger.Error(err)
			err = errors.ErrInternalServerError
		}

		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, err)
	}
	if accessToken == nil {
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
	}

	githubUserDetails, err := oauthS.GetGitHubUser(*accessToken)
	if err != nil || githubUserDetails == nil {
		if err != nil {
			err = errors.ErrInternalServerError
		} else {
			err = errors.ErrUnauthorized
		}

		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, err)
	}

	fmt.Printf("userDetails: %v\n", githubUserDetails)

	var provderDetails models.OAuth
	err = o.Conn.DB.Where(models.OAuth{
		Provider:   enums.GitHub,
		ProviderID: fmt.Sprint(githubUserDetails.ID),
	}).First(&provderDetails).Error
	if err == nil {
		user, err := userS.GetUserWithID(*provderDetails.UserID)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				err = errors.ErrUnauthorized
			} else {
				logger.Error(err)
				err = errors.ErrInternalServerError
			}

			return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
		}

		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, nil)
	}
	if err != gorm.ErrRecordNotFound {
		logger.Error(err)
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
	}
	githubUserDetails.GetEmailFromPayload()

	if githubUserDetails.Email == nil {
		user, err := oauthS.CreateGitHubUserByCheckingUsername(&userS, githubUserDetails, nil)
		if err != nil {
			switch err {
			case errors.ErrBadRequest:
				err = errors.ErrBadRequest
			case errors.ErrUsernameAlreadyUsed:
				err = errors.ErrUsernameAlreadyUsed
			case errors.ErrAddAUsername:
				err = utils.GenerateOAuthCookie(c, o.Conn, o.Env, *accessToken, enums.GitHub)
				if err != nil {
					logger.Error(err)
					err = errors.ErrInternalServerError
				} else {
					err = errors.ErrAddAUsername
				}
			default:
				logger.Error(err)
				err = errors.ErrInternalServerError
			}

			return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
		}

		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, nil)
	}

	_, err = userS.GetUserWithEmail(*githubUserDetails.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Error(err)
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
	}
	if err == gorm.ErrRecordNotFound {
		user, err := oauthS.CreateGitHubUserByCheckingUsername(&userS, githubUserDetails, nil)
		if err != nil {
			switch err {
			case errors.ErrBadRequest:
				err = errors.ErrBadRequest
			case errors.ErrUsernameAlreadyUsed:
				err = errors.ErrUsernameAlreadyUsed
			case errors.ErrAddAUsername:
				err = utils.GenerateOAuthCookie(c, o.Conn, o.Env, *accessToken, enums.GitHub)
				if err != nil {
					logger.Error(err)
					err = errors.ErrInternalServerError
				} else {
					err = errors.ErrAddAUsername
				}
			default:
				logger.Error(err)
				err = errors.ErrInternalServerError
			}

			return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
		}
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, nil)
	}

	return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrLinkAccountWithEmail)
}

// GitHubOAuthRegisterWithUsername is a function that is used to register the GitHub user with the given username
func (o *OAuth) GitHubOAuthRegisterWithUsername(c *fiber.Ctx) error {
	username := c.Params("username", "")
	fmt.Printf("username: %v\n", username)

	oauthTokenC := c.Cookies("oauth_token")
	fmt.Printf("oauthTokenC: %v\n", oauthTokenC)
	if oauthTokenC == "" {
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrBadRequest)
	}

	oauthTokenS := token.OAuthToken{
		Conn:     o.Conn,
		Env:      o.Env,
		Provider: enums.GitHub,
	}

	token, err := oauthTokenS.Validate(oauthTokenC)
	if err != nil {
		if isExpired := (errors.CheckTokenError{}.Expired(err)); isExpired {
			return c.Redirect("/oauth/github/redirect")
		}

		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrBadRequest)
	}

	tokenDetails, err := oauthTokenS.GetOAuthTokenDetails(token)
	if err != nil {
		logger.Error(err)
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
	}

	oauthS := services.OAuth{
		Conn: o.Conn,
		Env:  o.Env,
	}

	userS := services.User{
		Conn: o.Conn,
	}

	fmt.Printf("tokenDetails.AccessToken: %v\n", tokenDetails.AccessToken)

	githubUserDetails, err := oauthS.GetGitHubUser(tokenDetails.AccessToken)
	fmt.Println("I am in this line 233")
	if err != nil {
		fmt.Printf("err: %v\n", err)
		if err == errors.ErrCouldNotGetUserFromOAuthProvider {
			return c.Redirect("/oauth/github/redirect")
		}

		logger.Error(err)
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
	}

	user, err := oauthS.CreateGitHubUserByCheckingUsername(&userS, githubUserDetails, &username)
	fmt.Printf("err: %v\n", err)
	if err != nil {
		switch err {
		case errors.ErrBadRequest:
			err = errors.ErrBadRequest
		case errors.ErrUsernameAlreadyUsed:
			err = errors.ErrUsernameAlreadyUsed
		default:
			logger.Error(err)
			err = errors.ErrInternalServerError
		}

		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, err)
	}

	err = utils.GenerateCookies(c, user, o.Conn, o.Env)
	if err != nil {
		logger.Error(err)
		return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, errors.ErrInternalServerError)
	}

	return errors.OAuthStateRedirect(c, o.Env, enums.GitHub, nil)
}
