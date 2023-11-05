package config

import (
	"time"

	"github.com/VinukaThejana/go-utils/logger"
	"github.com/spf13/viper"
)

// Env is structure containing env variables
type Env struct {
	Port                     string        `mapstructure:"PORT" validate:"required,numeric"`
	DevEnv                   string        `mapstructure:"DEV_ENV" validate:"required,oneof=DEV PROD TEST"`
	DSN                      string        `mapstructure:"DATABASE_URL" validate:"required"`
	RedisRatelimiterUsername string        `mapstructure:"REDIS_RATELIMITER_USERNAME"`
	RedisRatelimiterPassword string        `mapstructure:"REDIS_RATELIMITER_PASSWORD"`
	RedisRatelimiterHost     string        `mapstructure:"REDIS_RATELIMITER_HOST" validate:"required"`
	RedisRatelimiterPort     int           `mapstructure:"REDIS_RATELIMITER_PORT" validate:"required,number"`
	RedisSessionURL          string        `mapstructure:"REDIS_SESSION_URL" validate:"required,uri"`
	RedisEmailURL            string        `mapstructure:"REDIS_EMAIL_URL" validate:"required,uri"`
	RedisSystemURL           string        `mapstructure:"REDIS_SYSTEM_URL" validate:"required,uri"`
	RedisChallengeURL        string        `mapstructure:"REDIS_CHALLENGE_URL" validate:"required,uri"`
	AccessTokenPrivateKey    string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY" validate:"required"`
	AccessTokenPublicKey     string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY" validate:"required"`
	AccessTokenExpires       time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRED_IN" validate:"required"`
	AccessTokenMaxAge        int           `mapstructure:"ACCESS_TOKEN_MAXAGE" validate:"required,number"`
	RefreshTokenPrivateKey   string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY" validate:"required"`
	RefreshTokenPublicKey    string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY" validate:"required"`
	RefreshTokenExpires      time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRED_IN" validate:"required"`
	RefreshTokenMaxAge       int           `mapstructure:"REFRESH_TOKEN_MAXAGE" validate:"required,number"`
	SessionSecret            string        `mapstructure:"SESSION_SECRET" validate:"required"`
	AuthConfirmTokenSecret   string        `mapstructure:"AUTH_CONFIRM_TOKEN_SECRET" validate:"required"`
	ResendAPIKey             string        `mapstructure:"RESEND_API_KEY" validate:"required"`
	FrontendHostname         string        `mapstructure:"FRONTEND_HOSTNAME" validate:"required,hostname"`
	FrontendURL              string        `mapstructure:"FRONTEND_URL" validate:"required,url"`
}

// Load is a function that is used to laod the env variables from the file and the enviroment
func (e *Env) Load() {
	viper.AddConfigPath(".")
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		logger.Error(err)
	}

	err = viper.Unmarshal(&e)
	if err != nil {
		logger.Errorf(err)
	}

	logger.Validatef(e)
}
