// Auth is a backend for authentication
package main

import (
	"fmt"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/controllers"
	"github.com/VinukaThejana/auth/middleware"
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

	authM middleware.Auth

	systemC controllers.System
	authC   controllers.Auth
	oauthC  controllers.OAuth
	emailC  controllers.Email
	userC   controllers.User
	adminC  controllers.Admin
)

func init() {
	env.Load()

	conn.InitDatabase(&env)
	utils.CheckForMigrations(&conn, &env)

	conn.InitRatelimiter(&env)
	conn.InitRedis(&env)
	conn.InitMinioClient(&env)

	authM = middleware.Auth{
		Conn: &conn,
		Env:  &env,
	}

	systemC = controllers.System{
		Conn: &conn,
	}
	authC = controllers.Auth{
		Conn: &conn,
		Env:  &env,
	}
	oauthC = controllers.OAuth{
		Conn: &conn,
		Env:  &env,
	}
	emailC = controllers.Email{
		Conn: &conn,
		Env:  &env,
	}
	userC = controllers.User{
		Conn: &conn,
		Env:  &env,
	}
	adminC = controllers.Admin{
		Conn: &conn,
		Env:  &env,
	}
}

func main() {
	app := fiber.New()
	if config.GetDevEnv(&env) == config.Dev {
		app.Use(fiberLogger.New())
	}

	app.Use(cors.New(cors.Config{
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowOrigins:     env.FrontendURL,
		AllowCredentials: true,
		AllowMethods:     "GET, POST, DELETE",
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
			Title: "Monitor auth backend",
		}))
		router.Get("/health", systemC.Health)
	})

	app.Route("/auth", func(router fiber.Router) {
		router.Post("/register", authC.RegisterWEmailAndPassword)
		router.Post("/login", authM.GetUA, authC.LoginWEmailAndPassword)
		router.Delete("/logout", authM.CheckRefreshToken, authC.Logout)
		router.Post("/refresh", authM.CheckRefreshToken, authC.RefreshAccessToken)
		router.Route("/reauthenticate", func(router fiber.Router) {
			router.Post("/password", authM.Check, authC.ReAuthenticateWithPassword)
			router.Post("/passkey", authM.Check, authC.ReAuthenticateWithPassKey)
		})

		router.Route("/passkeys", func(router fiber.Router) {
			router.Get("/challenge", authC.GetChallenge)
			router.Post("/create", authM.Check, authC.CreatePassKey)
			router.Post("/login", authM.GetUA, authC.LoginWithPassKey)
			router.Get("/get", authM.Check, authC.GetPassKeys)
			router.Post("/edit", authM.Check, authC.EditPassKey)
			router.Post("/delete", authM.Check, authC.DeletePassKey)
		})

		router.Route("/otp", func(router fiber.Router) {
			router.Post("/generate", authM.Check, authM.CheckReAuthToken, authC.CreateTOTP)
			router.Post("/verify", authM.Check, authC.VerifyTOTP)
			router.Post("/reset", authC.ResetTwoFactorAuthentication)
			router.Post("/validate", authM.GetUA, authC.ValidateTOTPToken)
		})
	})

	app.Route("/oauth", func(router fiber.Router) {
		router.Route("/github", func(router fiber.Router) {
			router.Get("/redirect", oauthC.RedirectToGitHubOAuthFlow)
			router.Get("/callback", authM.GetUA, oauthC.GitHubCallback)
			router.Get("/add/username/:username", authM.GetUA, oauthC.AddUsernameGitHubOAuth)
			router.Get("/link", authM.GetUA, oauthC.LinkAccountsWGitHubProvider)
		})
	})

	app.Route("/user", func(router fiber.Router) {
		router.Route("/devices", func(router fiber.Router) {
			router.Get("/list", authM.Check, userC.GetLoggedInDevices)
			router.Post("/remove", authM.Check, authM.CheckReAuthToken, userC.LogoutFromDevices)
		})

		router.Route("/password", func(router fiber.Router) {
			router.Get("/status", authM.Check, userC.IsPasswordSet)
			router.Post("/add", authM.Check, userC.AddPassword)
		})
	})

	app.Route("/admin", func(router fiber.Router) {
		router.Route("/delete", func(router fiber.Router) {
			router.Get("/sessions", authM.CheckAdmin, adminC.DeleteExpiredSessions)
		})
	})

	app.Route("/check", func(router fiber.Router) {
		router.Post("/username", userC.CheckUsername)
	})

	app.Route("/email", func(router fiber.Router) {
		router.Get("/confirmation", emailC.ConfirmEmail)
	})

	logger.Errorf(app.Listen(fmt.Sprintf(":%s", env.Port)))
}
