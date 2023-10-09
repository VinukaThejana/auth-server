package connect

import (
	"context"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/gofiber/storage/redis"
)

// InitRatelimiter is a function that is used to initialize the ratelimiter storage
func (c *Connector) InitRatelimiter(env *config.Env) {
	store := redis.New(redis.Config{
		Username: env.RedisRatelimiterUsername,
		Password: env.RedisRatelimiterPassword,
		Host:     env.RedisRatelimiterHost,
		Port:     env.RedisRatelimiterPort,
	})
	err := store.Conn().Ping(context.Background()).Err()
	if err != nil {
		logger.Errorf(err)
	}

	c.Ratelimter = store
}
