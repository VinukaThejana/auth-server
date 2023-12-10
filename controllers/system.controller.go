package controllers

import (
	"context"
	"strconv"

	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/enums"
	"github.com/gofiber/fiber/v2"
)

// System is a struct that contains system level controllers
type System struct {
	Conn *connect.Connector
}

// Health is a function that is notifys the system health
func (s *System) Health(c *fiber.Ctx) error {
	var health bool
	var err error
	status := s.Conn.R.System.Get(context.TODO(), enums.SysHealth).Val()
	if status == "" {
		health = false
	} else {
		health, err = strconv.ParseBool(status)
		if err != nil {
			health = false
		}
	}

	msg := s.Conn.R.System.Get(context.TODO(), enums.SysHealthMsg).Val()
	if msg == "" {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"heatlh": health,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"health":  health,
		"message": msg,
	})
}
