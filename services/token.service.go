package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Token struct contains services related to tokens
type Token struct {
	Conn *connect.Connector
}

// DeleteTokenData is a function to delete the token data from the session database and the relataional database
func (t *Token) DeleteTokenData(refreshTokenUUID uuid.UUID) error {
	err := t.Conn.DB.Delete(&models.Sessions{
		ID: &refreshTokenUUID,
	}).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	ctx := context.TODO()
	detailsStr := t.Conn.R.Session.GetDel(ctx, refreshTokenUUID.String()).Val()
	if detailsStr == "" {
		return nil
	}

	var details schemas.RefreshTokenDetails
	err = json.Unmarshal([]byte(detailsStr), &details)
	if err != nil {
		return err
	}

	t.Conn.R.Session.Del(ctx, details.AccessTokenUUID)
	return nil
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
