package templates_test

import (
	"testing"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/utils"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/google/uuid"
)

var (
	env  config.Env
	conn connect.Connector
)

func init() {
	env.Load("./../")

	conn.InitRedis(&env)
	conn.InitDatabase(&env)
}

func TestGetEmailConfirmationTmpl(T *testing.T) {
	emailClient := utils.Email{
		Conn: &conn,
		Env:  &env,
	}

	args := []struct {
		Email string
		URL   string
		ID    uuid.UUID
	}{
		{},
	}

	for _, arg := range args {
		err := emailClient.SendConfirmation(arg.ID, arg.Email)
		if err != nil {
			logger.Error(err)
			T.Fail()
			continue
		}
	}
}

func TestPasswordResetTmpl(T *testing.T) {
	emailClient := utils.Email{
		Conn: &conn,
		Env:  &env,
	}

	args := []struct {
		Email string
		ID    uuid.UUID
	}{
		{},
	}

	for _, arg := range args {
		err := emailClient.ResetPassword(arg.ID, arg.Email)
		if err != nil {
			logger.Error(err)
			T.Fail()
			continue
		}
	}
}
