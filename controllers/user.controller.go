package controllers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/services"
	"github.com/VinukaThejana/auth/session"
	"github.com/VinukaThejana/auth/validate"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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
		Status      string `json:"status"`
		IsAvailable bool   `json:"is_available"`
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

// GetLoggedInDevices is a function that is used to get logged in devices of the given user
func (u *User) GetLoggedInDevices(c *fiber.Ctx) error {
	user := session.Get(c)

	var instances []models.Sessions
	err := u.Conn.DB.Where("user_id = ?", user.ID).Find(&instances).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   errors.Okay,
		"sessions": instances,
	})
}

// LogoutFromDevices is a function that is used to logout from a given device
func (u *User) LogoutFromDevices(c *fiber.Ctx) error {
	user := session.Get(c)

	var payload struct {
		ID string `json:"id"`
	}

	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	tokenUUID, err := uuid.Parse(payload.ID)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	err = u.Conn.DB.Delete(&models.Sessions{
		ID:     &tokenUUID,
		UserID: user.ID,
	}).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Unauthorized(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	ctx := context.TODO()

	detailsStr := u.Conn.R.Session.GetDel(ctx, tokenUUID.String()).Val()
	fmt.Printf("detailsStr: %v\n", detailsStr)
	if detailsStr != "" {
		var details schemas.RefreshTokenDetails
		err = json.Unmarshal([]byte(detailsStr), &details)
		if err == nil {
			u.Conn.R.Session.Del(ctx, details.UserID)
		}
	}

	var details schemas.RefreshTokenDetails
	err = json.Unmarshal([]byte(detailsStr), &details)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	err = u.Conn.R.Session.Del(ctx, details.AccessTokenUUID).Err()
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return errors.Done(c)
}

// IsPasswordSet is a function that is used to check wether the user have set the password or not
func (u *User) IsPasswordSet(c *fiber.Ctx) error {
	user := session.Get(c)

	var userM models.User
	err := u.Conn.DB.Select("password").Where(&models.User{
		ID: user.ID,
	}).First(&userM).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Unauthorized(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"is_password_set": userM.Password != "",
	})
}

// AddPassword is a function that is used to add a passowrd for a user where the password is not present
func (u *User) AddPassword(c *fiber.Ctx) error {
	var payload struct {
		Password string `json:"password" validate:"required,min=8,max=200,validate_password"`
	}
	if err := c.BodyParser(&payload); err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	v := validator.New()
	v.RegisterValidation("validate_password", validate.Password)
	err := v.Struct(payload)
	if err != nil {
		logger.Error(err)
		return errors.BadRequest(c)
	}

	user := session.Get(c)
	userS := services.User{
		Conn: u.Conn,
	}

	userM, err := userS.GetUserWithID(*user.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Unauthorized(c)
		}

		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	if userM.Password != "" {
		return errors.BadRequest(c)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost)
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	userM.Password = string(hashedPassword)
	err = u.Conn.DB.Save(userM).Error
	if err != nil {
		logger.Error(err)
		return errors.InternalServerErr(c)
	}

	return errors.Done(c)
}
