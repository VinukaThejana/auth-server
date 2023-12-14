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
	"github.com/VinukaThejana/auth/validate"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/go-playground/validator/v10"
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
	redirect := errors.Redirect{
		C:        c,
		Env:      o.Env,
		Provider: enums.GitHub,
	}

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

		return redirect.WithState(err)
	}
	if accessToken == nil {
		return redirect.WithState(errors.ErrInternalServerError)
	}

	githubUserDetails, err := oauthS.GetGitHubUser(*accessToken)
	if err != nil || githubUserDetails == nil {
		if err != nil {
			err = errors.ErrInternalServerError
		} else {
			err = errors.ErrUnauthorized
		}

		return redirect.WithState(err)
	}

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

			return redirect.WithState(err)
		}

		err = utils.GenerateCookies(c, user, o.Conn, o.Env)
		if err != nil {
			logger.Error(err)
			return redirect.WithState(err)
		}

		return redirect.WithState(nil)
	}
	if err != gorm.ErrRecordNotFound {
		logger.Error(err)
		return redirect.WithState(errors.ErrInternalServerError)
	}
	err = githubUserDetails.GetEmailFromPayload()
	if err != nil {
		return redirect.WithState(errors.ErrInternalServerError)
	}

	user, err := oauthS.CreateGitHubUser(&userS, githubUserDetails)
	if err != nil {
		switch err {
		case errors.ErrBadRequest:
			break
		case errors.ErrAddAUsername:
			err = utils.GenerateOAuthCookie(c, o.Conn, o.Env, *accessToken, enums.GitHub)
			if err != nil {
				logger.Error(err)
				err = errors.ErrInternalServerError
			} else {
				err = errors.ErrAddAUsername
			}
		case errors.ErrLinkAccountWithEmail:
			break
		default:
			logger.Error(err)
			err = errors.ErrInternalServerError
		}

		return redirect.WithState(err)
	}

	err = utils.GenerateCookies(c, user, o.Conn, o.Env)
	if err != nil {
		logger.Error(err)
		redirect.WithState(errors.ErrInternalServerError)
	}

	return redirect.WithState(nil)
}

// AddUsernameGitHubOAuth is a function that is used to register the GitHub user with the given username
func (o *OAuth) AddUsernameGitHubOAuth(c *fiber.Ctx) error {
	redirect := errors.Redirect{
		C:        c,
		Env:      o.Env,
		Provider: enums.GitHub,
	}

	payload := struct {
		Username string `json:"username" validate:"required,min=3,max=20,validate_username"`
	}{
		Username: c.Params("username", ""),
	}

	v := validator.New()
	v.RegisterValidation("validate_username", validate.Username)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return redirect.WithState(errors.ErrBadRequest)
	}

	oauthTokenC := c.Cookies("oauth_token")
	if oauthTokenC == "" {
		return c.Redirect("/oauth/github/redirect")
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

		return redirect.WithState(errors.ErrBadRequest)
	}

	tokenDetails, err := oauthTokenS.GetOAuthTokenDetails(token)
	if err != nil {
		logger.Error(err)
		return redirect.WithState(errors.ErrInternalServerError)
	}

	oauthS := services.OAuth{
		Conn: o.Conn,
		Env:  o.Env,
	}

	userS := services.User{
		Conn: o.Conn,
	}

	githubUserDetails, err := oauthS.GetGitHubUser(tokenDetails.AccessToken)
	if err != nil {
		if err == errors.ErrCouldNotGetUserFromOAuthProvider {
			return c.Redirect("/oauth/github/redirect")
		}

		logger.Error(err)
		return redirect.WithState(errors.ErrInternalServerError)
	}

	user, err := oauthS.CreateGithHubUserWithCustomUsername(&userS, githubUserDetails, payload.Username)
	if err != nil {
		switch err {
		case errors.ErrBadRequest:
			break
		case errors.ErrUsernameAlreadyUsed:
			break
		case errors.ErrLinkAccountWithEmail:
			break
		default:
			logger.Error(err)
			err = errors.ErrInternalServerError
		}

		return redirect.WithState(err)
	}

	err = utils.GenerateCookies(c, user, o.Conn, o.Env)
	if err != nil {
		logger.Error(err)
		return redirect.WithState(errors.ErrInternalServerError)
	}

	return redirect.WithState(nil)
}
