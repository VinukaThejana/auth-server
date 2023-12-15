package controllers

import (
	"context"
	"strings"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Email is a struct that contains email related controllers
type Email struct {
	Conn *connect.Connector
	Env  *config.Env
}

// ConfirmEmail is function that is used to verify the email
func (e *Email) ConfirmEmail(c *fiber.Ctx) error {
	token := c.Query("token", "")
	if token == "" {
		return errors.BadRequest(c)
	}

	if _, err := uuid.Parse(token); err != nil {
		return errors.BadRequest(c)
	}

	ctx := context.TODO()

	val := e.Conn.R.Email.Get(ctx, token).Val()
	if val == "" {
		return errors.BadRequest(c)
	}

	var user struct {
		ID    string
		Email string
	}

	var found bool
	user.ID, user.Email, found = strings.Cut(val, "+")
	if !found {
		return errors.ErrUnauthorized
	}

	userID, err := uuid.Parse(user.ID)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	err = e.Conn.DB.Model(&models.User{}).Where(&models.User{
		ID:    &userID,
		Email: user.Email,
	}).Update("verified", true).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrUnauthorized
		}

		return err
	}

	return errors.Done(c)
}
