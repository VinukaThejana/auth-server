package utils

import (
	"context"
	"fmt"
	"strings"
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
	Conn   *connect.Connector
	Env    *config.Env
	UserID uuid.UUID
}

// SendConfirmation is a function that is sent to the user inorder to confirm the user email address
func (e *Email) SendConfirmation(email string) {
	token := uuid.New()
	e.Conn.R.Email.SetNX(context.TODO(), token.String(), fmt.Sprintf("%s+%s", e.UserID.String(), email), emailConfirmationExpirationTime)

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

	logger.Log(fmt.Sprintf("Email sent with ID : %s", send.Id))
}

// ConfirmEmail is a function that is used to verify the email address
func (e *Email) ConfirmEmail(token string) error {
	var user struct {
		ID    string
		Email string
	}

	_, err := uuid.Parse(token)
	if err != nil {
		return err
	}

	ctx := context.TODO()

	val := e.Conn.R.Email.Get(ctx, token).Val()
	if val == "" {
		return errors.ErrEmailConfirmationExpired
	}

	var found bool
	user.ID, user.Email, found = strings.Cut(val, "+")
	if !found {
		return errors.ErrUnauthorized
	}

	if user.ID != e.UserID.String() {
		return errors.ErrUnauthorized
	}

	err = e.Conn.DB.Model(&models.User{}).Where(&models.User{
		ID:    &e.UserID,
		Email: user.Email,
	}).Update("verified", true).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrUnauthorized
		}

		return err
	}

	e.Conn.R.Email.Del(ctx, token)
	return nil
}
