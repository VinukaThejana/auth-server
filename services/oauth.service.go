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
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/validate"
	"github.com/go-playground/validator/v10"
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
		ID:        int(payload["id"].(float64)),
		Name:      payload["name"].(string),
		Username:  payload["login"].(string),
		AvatarURL: payload["avatar_url"].(string),
		Email:     nil,
	}
	github.GetEmailFromPayload(payload)

	return &github, nil
}

// CreateGitHubUserByCheckingUsername is a function that is used to create a user by using the github oauth details by checking the availability
// of the given username by GitHub oauth provider or the custom provided username by the user
func (o *OAuth) CreateGitHubUserByCheckingUsername(userS *User, userDetails *schemas.GitHub, username, provider string) (user *models.User, err error) {
	ok, isVerified, err := userS.IsUsernameAvailable(userDetails.Username)
	if err != nil {
		return nil, err
	}
	if !ok {
		if isVerified {
			if username == "" {
				return nil, errors.ErrAddAUsername
			}

			payload := struct {
				username string `validate:"required,min=3,max=20,validate_username"`
			}{
				username: username,
			}
			v := validator.New()
			v.RegisterValidation("validate_username", validate.Username)
			err := v.Struct(payload)
			if err != nil {
				return nil, errors.ErrBadRequest
			}

			ok, isVerified, err = userS.IsUsernameAvailable(payload.username)
			if err != nil {
				return nil, err
			}
			if !ok && isVerified {
				return nil, errors.ErrUsernameAlreadyUsed
			}

			userDetails.Username = payload.username
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
		Provider:   provider,
		ProviderID: fmt.Sprint(userDetails.ID),
		UserID:     userM.ID,
	}).Error
	if err != nil {
		return nil, err
	}

	return &userM, nil
}
