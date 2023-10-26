// Package session contains session related activity
package session

import (
	"strconv"

	"github.com/VinukaThejana/auth/schemas"
	"github.com/gofiber/fiber/v2"
)

// Add is a function that is used to add ther user details to the session
func Add(c *fiber.Ctx, user *schemas.User) {
	if user == nil {
		return
	}

	c.Locals("id", user.ID)
	c.Locals("name", user.Username)
	c.Locals("username", user.Username)
	c.Locals("email", user.Email)
	c.Locals("photo_url", user.PhotoURL)
	c.Locals("two_factor_enabled", user.TwoFactorEnabled)
}

// Get the user details from the session
func Get(c *fiber.Ctx) (user *schemas.User, err error) {
	twoFactorEnabled, err := strconv.ParseBool(c.Locals("two_factor_enabled").(string))
	if err != nil {
		return nil, err
	}

	return &schemas.User{
		ID:               c.Locals("id").(string),
		Name:             c.Locals("name").(string),
		Username:         c.Locals("username").(string),
		Email:            c.Locals("email").(string),
		PhotoURL:         c.Locals("photo_url").(string),
		TwoFactorEnabled: twoFactorEnabled,
	}, nil
}

// SaveSessionToken save the session token
func SaveSessionToken(c *fiber.Ctx, token string) {
	c.Locals("session_token", token)
}

// SaveRefreshToken save the refresh token
func SaveRefreshToken(c *fiber.Ctx, token string) {
	c.Locals("refresh_token", token)
}

// SaveAccessToken save the access token
func SaveAccessToken(c *fiber.Ctx, token string) {
	c.Locals("access_token", token)
}

// GetSessionToken get the session token
func GetSessionToken(c *fiber.Ctx) string {
	return c.Locals("session_token").(string)
}

// GetRefreshToken get the refresh token
func GetRefreshToken(c *fiber.Ctx) string {
	return c.Locals("refresh_token").(string)
}

// GetAccessToken get the access token
func GetAccessToken(c *fiber.Ctx) string {
	return c.Locals("access_token").(string)
}
