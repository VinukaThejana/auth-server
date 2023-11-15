package services

import (
	"time"

	"github.com/VinukaThejana/auth/connect"
	"github.com/gofiber/fiber/v2"
)

// Token struct contains services related to tokens
type Token struct {
	Conn *connect.Connector
}

// DeleteCookies is a funciton that is used to delete the access_token, refresh_token and the session token
func (t *Token) DeleteCookies(c *fiber.Ctx) {
	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "access_token",
		Value:   "",
		Expires: expired,
	})

	c.Cookie(&fiber.Cookie{
		Name:    "refresh_token",
		Value:   "",
		Expires: expired,
	})

	c.Cookie(&fiber.Cookie{
		Name:    "session",
		Value:   "",
		Expires: expired,
	})
}
