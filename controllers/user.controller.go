package controllers

import (
	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/services"
	"github.com/VinukaThejana/auth/validate"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

// User is a struct that contains user controllers
type User struct {
	Conn *connect.Connector
	Env  *config.Env
}

// CheckUsername is a function that is used to check ther username of the user
func (u *User) CheckUsername(c *fiber.Ctx) error {
	var payload struct {
		Username string `json:"username" validate:"required,min=3,max=20,validate_username"`
	}

	type res struct {
		IsAvailable bool   `json:"is_available"`
		Status      string `json:"status"`
	}

	if err := c.BodyParser(&payload); err != nil {

		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_username", validate.Username)
	v.RegisterValidation("validate_password", validate.Password)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return c.Status(fiber.StatusOK).JSON(res{
			IsAvailable: false,
			Status:      errors.ErrBadRequest.Error(),
		})
	}

	userS := services.User{
		Conn: u.Conn,
	}

	isAvailable, isVerified, err := userS.IsUsernameAvailable(payload.Username)
	if err != nil {
		logger.Error(err)
		return c.Status(fiber.StatusInternalServerError).JSON(res{
			IsAvailable: false,
			Status:      errors.ErrInternalServerError.Error(),
		})
	}
	if !isAvailable && !isVerified {
		isAvailable = true
	}

	return c.Status(fiber.StatusOK).JSON(res{
		IsAvailable: isAvailable,
		Status:      errors.Okay,
	})
}
