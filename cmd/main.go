// Auth is a backend for authentication
package main

import (
	"fmt"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/utils"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	fiberLogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/monitor"
)

var (
	env  config.Env
	conn connect.Connector
)

func init() {
	env.Load()

	conn.InitDatabase(&env)
	utils.CheckForMigrations(&conn, &env)

	conn.InitRatelimiter(&env)
	conn.InitRedis(&env)
}

func main() {
	app := fiber.New()
	if config.GetDevEnv(&env) == config.Dev {
		app.Use(fiberLogger.New())
	}

	app.Use(cors.New(cors.Config{
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowOrigins:     env.FrontendHostname,
		AllowCredentials: true,
		AllowMethods:     "*",
	}))

	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusTooManyRequests)
		},
		SkipFailedRequests:     false,
		SkipSuccessfulRequests: false,
		LimiterMiddleware:      limiter.SlidingWindow{},
		Storage:                conn.Ratelimter,
	}))

	app.Route("/monitor", func(router fiber.Router) {
		router.Get("/metrics", monitor.New(monitor.Config{
			Title: "Monitor Auth",
		}))
	})

	logger.Errorf(app.Listen(fmt.Sprintf(":%s", env.Port)))
}
