package connect

import (
	"context"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/redis/go-redis/v9"
)

// Redis is used to manage al redis service connections
type Redis struct {
	Session *redis.Client
	Email   *redis.Client
	System  *redis.Client
}

func connect(url string) *redis.Client {
	opt, err := redis.ParseURL(url)
	if err != nil {
		logger.Errorf(err)
	}

	r := redis.NewClient(opt)
	if err := r.Ping(context.Background()).Err(); err != nil {
		logger.Errorf(err)
	}

	return r
}

// InitRedis is a function to initialize all redis instances
func (c *Connector) InitRedis(env *config.Env) {
	c.R = &Redis{
		Session: connect(env.RedisSessionURL),
		Email:   connect(env.RedisEmailURL),
		System:  connect(env.RedisSystemURL),
	}
}
