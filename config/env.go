package config

import (
	"time"

	"github.com/VinukaThejana/go-utils/logger"
	"github.com/spf13/viper"
)

// Env is structure containing env variables
type Env struct {
	ResendAPIKey             string        `mapstructure:"RESEND_API_KEY" validate:"required"`
	DSN                      string        `mapstructure:"DATABASE_URL" validate:"required"`
	RefreshTokenPrivateKey   string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY" validate:"required"`
	RedisRatelimiterUsername string        `mapstructure:"REDIS_RATELIMITER_USERNAME"`
	RedisRatelimiterPassword string        `mapstructure:"REDIS_RATELIMITER_PASSWORD"`
	RedisRatelimiterHost     string        `mapstructure:"REDIS_RATELIMITER_HOST" validate:"required"`
	GitHubRedirectURL        string        `mapstructure:"GITHUB_REDIRECT_URL" validate:"required,url"`
	RedisSessionURL          string        `mapstructure:"REDIS_SESSION_URL" validate:"required,uri"`
	RedisEmailURL            string        `mapstructure:"REDIS_EMAIL_URL" validate:"required,uri"`
	RedisSystemURL           string        `mapstructure:"REDIS_SYSTEM_URL" validate:"required,uri"`
	RedisChallengeURL        string        `mapstructure:"REDIS_CHALLENGE_URL" validate:"required,uri"`
	AccessTokenPrivateKey    string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY" validate:"required"`
	AccessTokenPublicKey     string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY" validate:"required"`
	GitHubFromURL            string        `mapstructure:"GITHUB_FROM_URL" validate:"required,url"`
	GitHubRootURL            string        `mapstructure:"GITHUB_ROOT_URL" validate:"required,url"`
	DevEnv                   string        `mapstructure:"DEV_ENV" validate:"required,oneof=DEV PROD TEST"`
	RefreshTokenPublicKey    string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY" validate:"required"`
	GitHubClientSecret       string        `mapstructure:"GITHUB_CLIENT_SECRET" validate:"required"`
	GitHubClientID           string        `mapstructure:"GITHUB_CLIENT_ID" validate:"required"`
	SessionSecret            string        `mapstructure:"SESSION_SECRET" validate:"required"`
	AuthConfirmTokenSecret   string        `mapstructure:"AUTH_CONFIRM_TOKEN_SECRET" validate:"required"`
	OAuthTokenSecret         string        `mapstructure:"OAUTH_TOKEN_SECRET" validate:"required"`
	Port                     string        `mapstructure:"PORT" validate:"required,numeric"`
	FrontendHostname         string        `mapstructure:"FRONTEND_HOSTNAME" validate:"required,hostname"`
	FrontendURL              string        `mapstructure:"FRONTEND_URL" validate:"required,url"`
	AdminSecret              string        `mapstructure:"ADMIN_SECRET" validate:"required"`
	GoogleMapsAPISecret      string        `mapstructure:"GOOGLE_MAPS_STATIC_API_KEY" validate:"required"`
	MinioEndpoint            string        `mapstructure:"MINIO_ENDPOINT" validate:"required"`
	MinioAPIKeyID            string        `mapstructure:"MINIO_API_KEY_ID" validate:"required"`
	MinioAPIKeySecret        string        `mapstructure:"MINIO_API_KEY_SECRET" validate:"required"`
	RefreshTokenMaxAge       int           `mapstructure:"REFRESH_TOKEN_MAXAGE" validate:"required,number"`
	RefreshTokenExpires      time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRED_IN" validate:"required"`
	AccessTokenExpires       time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRED_IN" validate:"required"`
	OAuthTokenExpires        time.Duration `mapstructure:"OAUTH_TOKEN_EXPIRED_IN" validate:"required"`
	RedisRatelimiterPort     int           `mapstructure:"REDIS_RATELIMITER_PORT" validate:"required,number"`
	AccessTokenMaxAge        int           `mapstructure:"ACCESS_TOKEN_MAXAGE" validate:"required,number"`
	OAuthTokenMaxAge         int           `mapstructure:"OAUTH_TOKEN_MAXAGE" validate:"required,number"`
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
