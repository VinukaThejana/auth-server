package controllers

import (
	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/services"
	"github.com/VinukaThejana/auth/utils"
	"github.com/VinukaThejana/auth/validate"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// Auth struct contains all the auth related controllers
type Auth struct {
	Conn *connect.Connector
	Env  *config.Env
}

// RegisterWEmailAndPassword is a function that is used to register users to the platfrom with email and password login method
func (a *Auth) RegisterWEmailAndPassword(c *fiber.Ctx) error {
	var payload struct {
		Name     string `json:"name" validate:"required,min=3,max=60"`
		Username string `json:"username" validate:"required,min=3,max=20,validate_username"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8,max=200,validate_password"`
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
		return errors.BadRequest(c)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	newUser := models.User{
		Name:     payload.Name,
		Username: payload.Username,
		Email:    payload.Email,
		Password: string(hashedPassword),
	}

	userS := services.User{
		Conn: a.Conn,
	}
	newUser, err = userS.Create(newUser)
	if err != nil {
		if ok := (errors.CheckDBError{}.DuplicateKey(err)); ok {
			return errors.UsernameAlreadyUsed(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	emailClient := utils.Email{
		Conn:   a.Conn,
		Env:    a.Env,
		UserID: *newUser.ID,
	}

	emailClient.SendConfirmation(newUser.Email)

	return c.Status(fiber.StatusOK).JSON(schemas.Res{
		Status: errors.Okay,
	})
}
