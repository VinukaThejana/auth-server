package controllers

import (
	"fmt"
	"net/url"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/gofiber/fiber/v2"
)

// OAuth is a struct that contains OAuth related controllers
type OAuth struct {
	Conn *connect.Connector
	Env  *config.Env
}

// RedirectToGitHubOAuthFlow is a function that is used to redirect the user to the GitHub oauth flow
func (o *OAuth) RedirectToGitHubOAuthFlow(c *fiber.Ctx) error {
	options := url.Values{
		"client_id":    []string{o.Env.GitHubClientID},
		"redirect_uri": []string{o.Env.GitHubRedirectURL},
		"scope":        []string{"user:email"},
		"state":        []string{o.Env.GitHubFromURL},
	}

	githubRedirectURL := fmt.Sprintf("%s?%s", o.Env.GitHubRootURL, options.Encode())
	return c.Redirect(githubRedirectURL)
}
