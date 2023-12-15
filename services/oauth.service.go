package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/enums"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/utils"
	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/gofiber/fiber/v2"
)

// OAuth struct contains services related oauth handlers
type OAuth struct {
	Conn *connect.Connector
	Env  *config.Env
}

// GetGitHubAccessToken is a function that is used to get the GitHub access token
func (o *OAuth) GetGitHubAccessToken(code string) (accessToken *string, err error) {
	client := http.Client{
		Timeout: 30 * time.Second,
	}

	query := url.Values{
		"code":          []string{code},
		"client_id":     []string{o.Env.GitHubClientID},
		"client_secret": []string{o.Env.GitHubClientSecret},
	}.Encode()

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://github.com/login/oauth/access_token?%s", bytes.NewBufferString(query)), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.ErrCouldNotParseAccessKeyFromOAuthProvider
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	parsedQuery, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}

	if len(parsedQuery["access_token"]) == 0 {
		return nil, errors.ErrCouldNotParseAccessKeyFromOAuthProvider
	}

	token := parsedQuery["access_token"][0]
	return &token, nil
}

// GetGitHubUser is a service that is used to get the GitHub from the GitHub oauth provider
func (o *OAuth) GetGitHubUser(accessToken string) (schema *schemas.GitHub, err error) {
	req, err := http.NewRequest(http.MethodGet, "http://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.ErrCouldNotGetUserFromOAuthProvider
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return nil, err
	}

	github := schemas.GitHub{
		ID:          int(payload["id"].(float64)),
		Name:        payload["name"].(string),
		Username:    payload["login"].(string),
		AvatarURL:   payload["avatar_url"].(string),
		AccessToken: accessToken,
		Payload:     payload,
		Email:       nil,
	}

	return &github, nil
}

// CreateGitHubUser is a function that is used to create a user in our database from the details obtained from the GitHub oauth provider
func (o *OAuth) CreateGitHubUser(userS *User, userDetails *schemas.GitHub) (user *models.User, err error) {
	err = checkGitHubEmailAvailability(userS, userDetails)
	if err != nil {
		return nil, err
	}

	ok, isVerified, err := userS.IsUsernameAvailable(userDetails.Username)
	if err != nil {
		return nil, err
	}
	if !ok {
		if isVerified {
			return nil, errors.ErrAddAUsername
		}
		err = userS.DeleteUserWUsername(userDetails.Username)
		if err != nil {
			return nil, err
		}
	}

	var userM models.User
	userM.Username = userDetails.Username
	userM.Name = userDetails.Name
	userM.PhotoURL = userDetails.AvatarURL
	userM.Verified = true
	if userDetails.Email != nil {
		userM.Email = *userDetails.Email
	}

	userM, err = userS.Create(userM)
	if err != nil {
		return nil, err
	}

	err = o.Conn.DB.Create(&models.OAuth{
		Provider:   enums.GitHub,
		ProviderID: fmt.Sprint(userDetails.ID),
		UserID:     userM.ID,
	}).Error
	if err != nil {
		return nil, err
	}

	return &userM, nil
}

// CreateGithHubUserWithCustomUsername is a function that is used ro create a user in the dabtabase with details obtained from GitHub oauth
// provider and the custom username provided by the user
func (o *OAuth) CreateGithHubUserWithCustomUsername(userS *User, userDetails *schemas.GitHub, username string) (user *models.User, err error) {
	err = checkGitHubEmailAvailability(userS, userDetails)
	if err != nil {
		return nil, err
	}

	ok, isVerified, err := userS.IsUsernameAvailable(username)
	if err != nil {
		return nil, err
	}

	if !ok {
		if isVerified {
			return nil, errors.ErrUsernameAlreadyUsed
		}

		err = userS.DeleteUserWUsername(username)
		if err != nil {
			return nil, err
		}
	}

	var newUser models.User
	newUser.Username = username
	newUser.Name = userDetails.Name
	newUser.PhotoURL = userDetails.AvatarURL
	newUser.Verified = true
	if userDetails.Email != nil {
		newUser.Email = *userDetails.Email
	}

	userM, err := userS.Create(newUser)
	if err != nil {
		return nil, err
	}

	err = o.Conn.DB.Create(&models.OAuth{
		Provider:   enums.GitHub,
		ProviderID: fmt.Sprint(userDetails.ID),
		UserID:     userM.ID,
	}).Error
	if err != nil {
		return nil, err
	}

	return &userM, nil
}

func checkGitHubEmailAvailability(userS *User, userDetails *schemas.GitHub) error {
	if userDetails.Email != nil {
		ok, isVerified, err := userS.IsEmailAvailable(*userDetails.Email)
		if err != nil {
			return err
		}

		if !ok {
			if isVerified {
				return errors.ErrLinkAccountWithEmail
			}

			err = userS.DeleteUserWEmail(*userDetails.Email)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// PrepareLinkAccountWEmail is a function that is used to prepare to link oauht account with db account
func (o *OAuth) PrepareLinkAccountWEmail(
	c *fiber.Ctx,
	userS *User,
	details *schemas.BasicOAuthProvider,
	accessToken,
	provider string,
) (
	oauthUser *string,
	dbUser *string,
	err error,
) {
	err = utils.GenerateOAuthCookie(c, o.Conn, o.Env, accessToken, provider)
	if err != nil {
		return nil, nil, err
	}

	dbUserM, err := userS.GetUserWithEmail(*details.Email)
	if err != nil {
		return nil, nil, err
	}

	oauthUserB, err := json.Marshal(details)
	if err != nil {
		return nil, nil, err
	}
	dbUserB, err := json.Marshal(schemas.FilterUser(*dbUserM))
	if err != nil {
		return nil, nil, err
	}

	oauthUserBase64 := base64url.Encode(oauthUserB)
	dbUserBase64 := base64url.Encode(dbUserB)

	return &oauthUserBase64, &dbUserBase64, nil
}
