package utils

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/templates"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/google/uuid"
	"github.com/resendlabs/resend-go"
	"gorm.io/gorm"
)

const (
	resendEmailFrom                 = "onboarding@resend.dev"
	resendReplyFrom                 = "onboarding@resend.dev"
	emailConfirmationExpirationTime = 30 * 60 * time.Second
)

// Email is a struct that contains email related operations
type Email struct {
	Conn *connect.Connector
	Env  *config.Env
}

// SendConfirmation is a function that is sent to the user inorder to confirm the user email address
func (e *Email) SendConfirmation(userID uuid.UUID, email string) {
	token := uuid.New()
	e.Conn.R.Email.SetNX(context.TODO(), token.String(), fmt.Sprintf("%s+%s", userID.String(), email), emailConfirmationExpirationTime)

	emailTemplate, err := templates.Email{}.GetEmailConfirmationTmpl(
		fmt.Sprintf("http://localhost:8080/email/confirmation?token=%s", token.String()),
	)
	if err != nil {
		logger.Error(err)
		return
	}

	client := resend.NewClient(e.Env.ResendAPIKey)
	params := &resend.SendEmailRequest{
		From:    resendEmailFrom,
		To:      []string{email},
		Html:    emailTemplate,
		Subject: "Email confirmation",
		ReplyTo: resendReplyFrom,
	}
	send, err := client.Emails.Send(params)
	if err != nil {
		logger.Error(err)
		return
	}

	logger.Log(fmt.Sprintf("[ %s ] : Confirmation email sent", send.Id))
}

// ResendConfirmation is a funtion that is used to resend the confirmation email
func (e *Email) ResendConfirmation(userID uuid.UUID) error {
	var user models.User
	err := e.Conn.DB.Where(&models.User{
		ID: &userID,
	}).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrUnauthorized
		}

		return err
	}

	e.SendConfirmation(userID, user.Email)
	return nil
}

// ResetPassword is a function that is used to send the OTP that is used to reset the users password
func (e *Email) ResetPassword(userID uuid.UUID, email string) error {
	otp := fmt.Sprintf(
		"%d%d%d-%d%d%d",
		rand.Intn(10),
		rand.Intn(10),
		rand.Intn(10),
		rand.Intn(10),
		rand.Intn(10),
		rand.Intn(10),
	)
	err := e.Conn.R.Challenge.SetNX(
		context.Background(),
		fmt.Sprintf("%s_pw_reset", userID.String()),
		otp,
		time.Second*60*60*2,
	).Err()
	if err != nil {
		return err
	}

	emailTemplate, err := templates.Email{}.PasswordResetTmpl(otp)
	if err != nil {
		return err
	}

	client := resend.NewClient(e.Env.ResendAPIKey)
	params := &resend.SendEmailRequest{
		From:    resendEmailFrom,
		To:      []string{email},
		Html:    emailTemplate,
		Subject: "Password Reset",
		ReplyTo: resendReplyFrom,
	}

	_, err = client.Emails.Send(params)
	if err != nil {
		return err
	}

	return nil
}
