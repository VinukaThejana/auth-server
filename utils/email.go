package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/templates"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/google/uuid"
	"github.com/resendlabs/resend-go"
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

	logger.Log(fmt.Sprintf("[ %s ] : Confirmation email sent", send.Id))
}
