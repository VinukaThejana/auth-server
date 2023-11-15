package controllers

import (
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/gofiber/fiber/v2"
)

// Admin is a struct that contains all the admin related controllers
type Admin struct {
	Conn *connect.Connector
	Env  *config.Env
}

// DeleteExpiredSessions is a fucntion that is used to delete expired sessions from the database
func (a *Admin) DeleteExpiredSessions(c *fiber.Ctx) error {
	now := time.Now().UTC()

	err := a.Conn.DB.Where("expires_at <= ?", now.Unix()).Delete(&models.Sessions{}).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: errors.Okay,
	})
}
