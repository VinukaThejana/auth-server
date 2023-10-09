package config

import (
	"time"

	"github.com/VinukaThejana/go-utils/logger"
	"github.com/spf13/viper"
)

// Env is structure containing env variables
type Env struct {
	RedisEmailURL          string        `mapstructure:"REDIS_EMAIL_URL" validate:"required"`
	ResendAPIKey           string        `mapstructure:"RESEND_API_KEY" validate:"required"`
	DBHost                 string        `mapstructure:"POSTGRES_HOST" validate:"required"`
	DBPassword             string        `mapstructure:"POSTGRES_PASSWORD" validate:"required"`
	DBName                 string        `mapstructure:"POSTGRES_DB" validate:"required"`
	DSN                    string        `mapstructure:"DATABASE_URL" validate:"required"`
	RedisSessionURL        string        `mapstructure:"REDIS_SESSION_URL" validate:"required"`
	RedisRatelimiterURL    string        `mapstructure:"REDIS_RATELIMITER_URL" validate:"required"`
	DBUser                 string        `mapstructure:"POSTGRES_USER" validate:"required,min=3,max=15"`
	Port                   string        `mapstructure:"PORT" validate:"required"`
	AccessTokenPublicKey   string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY" validate:"required"`
	AccessTokenPrivateKey  string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY" validate:"required"`
	RefreshTokenPublicKey  string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY" validate:"required"`
	RefreshTokenPrivateKey string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY" validate:"required"`
	AccessTokenMaxAge      int           `mapstructure:"ACCESS_TOKEN_MAXAGE" validate:"required"`
	AccessTokenExpires     time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRED_IN" validate:"required"`
	RefreshTokenExpires    time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRED_IN" validate:"required"`
	RefreshTokenMaxAge     int           `mapstructure:"REFRESH_TOKEN_MAXAGE" validate:"required"`
	DBPort                 int           `mapstructure:"POSTGRES_PORT" validate:"required,min=1,max=65535"`
	DevEnv                 string        `mapstructure:"DEV_ENV" validate:"required,oneof=PROD DEV TEST"`
}

// Load is a function that is used to laod the env variables from the file and the enviroment
func (e *Env) Load() {
	viper.AddConfigPath(".")
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		logger.Errorf(err)
	}

	logger.Validatef(e)
}
