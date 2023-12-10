package controllers

import (
	"fmt"
	"net/url"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/services"
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
	username := c.Query("username")

	options := url.Values{
		"client_id":    []string{o.Env.GitHubClientID},
		"redirect_uri": []string{o.Env.GitHubRedirectURL},
		"scope":        []string{"user:email"},
		"state":        []string{username},
	}

	githubRedirectURL := fmt.Sprintf("%s?%s", o.Env.GitHubRootURL, options.Encode())
	fmt.Printf("githubRedirectURL: %v\n", githubRedirectURL)
	return c.Redirect(githubRedirectURL)
}

// GitHubCallback is the callback handler that GitHub responds to
func (o *OAuth) GitHubCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	username := c.Query("state")

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

		return errors.RedirectToTheFrontendWithErrState(c, o.Env, err)
	}
	if accessToken == nil {
		return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrInternalServerError)
	}

	userDetails, err := oauthS.GetGitHubUser(*accessToken)
	if err != nil || userDetails == nil {
		if err != nil {
			err = errors.ErrInternalServerError
		} else {
			err = errors.ErrUnauthorized
		}

		return errors.RedirectToTheFrontendWithErrState(c, o.Env, err)
	}

	fmt.Printf("userDetails: %v\n", userDetails)
	const provider = "github"

	var provderDetails models.OAuth
	err = o.Conn.DB.Where(models.OAuth{
		Provider:   provider,
		ProviderID: fmt.Sprint(userDetails.ID),
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

			return errors.RedirectToTheFrontendWithErrState(c, o.Env, err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrInternalServerError)
		}

		return errors.RedirectToTheFrontendWithErrState(c, o.Env, nil)
	}
	if err != gorm.ErrRecordNotFound {
		logger.Error(err)
		return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrInternalServerError)
	}

	if userDetails.Email == nil {
		user, err := oauthS.CreateGitHubUserByCheckingUsername(&userS, userDetails, username, provider)
		if err != nil {
			switch err {
			case errors.ErrBadRequest:
				err = errors.ErrBadRequest
			case errors.ErrUsernameAlreadyUsed:
				err = errors.ErrUsernameAlreadyUsed
			case errors.ErrAddAUsername:
				err = errors.ErrAddAUsername
			default:
				logger.Error(err)
				err = errors.ErrInternalServerError
			}

			return errors.RedirectToTheFrontendWithErrState(c, o.Env, err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrInternalServerError)
		}

		return errors.RedirectToTheFrontendWithErrState(c, o.Env, nil)
	}

	_, err = userS.GetUserWithEmail(*userDetails.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Error(err)
		return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrInternalServerError)
	}
	if err == gorm.ErrRecordNotFound {
		user, err := oauthS.CreateGitHubUserByCheckingUsername(&userS, userDetails, username, provider)
		if err != nil {
			switch err {
			case errors.ErrBadRequest:
				err = errors.ErrBadRequest
			case errors.ErrUsernameAlreadyUsed:
				err = errors.ErrUsernameAlreadyUsed
			case errors.ErrAddAUsername:
				err = errors.ErrAddAUsername
			default:
				logger.Error(err)
				err = errors.ErrInternalServerError
			}

			return errors.RedirectToTheFrontendWithErrState(c, o.Env, err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrInternalServerError)
		}
		return errors.RedirectToTheFrontendWithErrState(c, o.Env, nil)
	}

	return errors.RedirectToTheFrontendWithErrState(c, o.Env, errors.ErrLinkAccountWithEmail)
}
