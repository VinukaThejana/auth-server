package schemas

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BasicOAuthProvider is struct with commom feilds provided by the oauth provider
type BasicOAuthProvider struct {
	Email    *string
	ID       string
	Name     string
	Username string
	PhotoURL string
}

// GitHub is a struct that contains details received from the GitHub oauth provider
type GitHub struct {
	Email       *string                `json:"email"`
	Payload     map[string]interface{} `json:"payload"`
	AccessToken string                 `json:"accessToken"`
	Name        string                 `json:"name"`
	Username    string                 `json:"login"`
	AvatarURL   string                 `json:"avatar_url"`
	ID          int                    `json:"id"`
}

// FilterToBasicOAuth is a function that is used to generate basic oauth feilds from the GitHub oauth provider
func (g *GitHub) FilterToBasicOAuth() *BasicOAuthProvider {
	return &BasicOAuthProvider{
		Email:    g.Email,
		ID:       fmt.Sprint(g.ID),
		Name:     g.Name,
		Username: g.Username,
		PhotoURL: g.AvatarURL,
	}
}

// GetEmailFromPayload is a helper method on GitHub to extract the email address from the payload received from GitHub
func (g *GitHub) GetEmailFromPayload() error {
	if email, ok := g.Payload["email"].(*string); ok && email != nil {
		g.Email = email
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, "http://api.github.com/user/emails", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.AccessToken))
	req.Header.Set("Accept", "application/vnd.github+json")

	client := http.Client{
		Timeout: 30 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("could not fetch the emails belonging to the user")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	type Email struct {
		Visibility string `json:"visibility,omitempty"`
		Email      string `json:"email"`
		Primary    bool   `json:"primary"`
		Verified   bool   `json:"verified"`
	}

	var emails []Email
	err = json.Unmarshal(body, &emails)
	if err != nil {
		return err
	}

	if len(emails) == 0 {
		g.Email = nil
		return nil
	}

	for _, email := range emails {
		// Ignore the auto generated email from GithHub
		if strings.HasSuffix(email.Email, "@users.noreply.github.com") {
			continue
		}

		if email.Primary && email.Verified {
			g.Email = &email.Email
			return nil
		}
	}

	g.Email = nil
	return nil
}
