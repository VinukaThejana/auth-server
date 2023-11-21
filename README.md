
# Auth Server

An authentication server with all modern authentication methods such as,
- PassKeys
- OAuth login with providers such as,
  - GitHub
  - Google
  - Twitter (X)

and with also support for 2 Factor authentication

## Links

- [API Documentation](https://documenter.getpostman.com/view/26265282/2s9YeAAaD4) 

- [Frontend Implementation](https://github.com/VinukaThejana/auth-website)

## How to get started ?

- Create a .env file in the below given format
```
ACCESS_TOKEN_EXPIRED_IN
ACCESS_TOKEN_MAXAGE
ACCESS_TOKEN_PRIVATE_KEY
ACCESS_TOKEN_PUBLIC_KEY
ADMIN_SECRET
AUTH_CONFIRM_TOKEN_SECRET
DATABASE_URL
DEV_ENV
DOPPLER_CONFIG
DOPPLER_ENVIRONMENT
DOPPLER_PROJECT
FRONTEND_HOSTNAME
FRONTEND_URL
PORT
POSTGRES_DB
POSTGRES_HOST
POSTGRES_PASSWORD
POSTGRES_PORT
POSTGRES_USER
REDIS_CHALLENGE_URL
REDIS_EMAIL_URL
REDIS_RATELIMITER_HOST
REDIS_RATELIMITER_PASSWORD
REDIS_RATELIMITER_PORT
REDIS_RATELIMITER_USERNAME
REDIS_SESSION_URL
REDIS_SYSTEM_URL
REFRESH_TOKEN_EXPIRED_IN
REFRESH_TOKEN_MAXAGE
REFRESH_TOKEN_PRIVATE_KEY
REFRESH_TOKEN_PUBLIC_KEY
RESEND_API_KEY
SESSION_SECRET
```
- Run `go mod tidy` 
- Run `docker compose up` 
- Run `go run cmd/main.go` 
