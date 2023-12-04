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
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/schemas"
)

// OAuth struct contains services related oauth handlers
type OAuth struct {
	Env *config.Env
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
