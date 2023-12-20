package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/auth/session"
	"github.com/VinukaThejana/auth/token"
	"github.com/gofiber/fiber/v2"
	"github.com/minio/minio-go/v7"
)

// GenerateCookies is a function that is used to generate cookies that are used to login the user
func GenerateCookies(c *fiber.Ctx, user *models.User, conn *connect.Connector, env *config.Env) error {
	refreshTokenS := token.RefreshToken{
		Conn:   conn,
		Env:    env,
		UserID: *user.ID,
	}
	accessTokenS := token.AccessToken{
		Conn:   conn,
		Env:    env,
		UserID: *user.ID,
	}
	sessionTokenS := token.SessionToken{
		Conn: conn,
		Env:  env,
	}

	var ip string

	ua := session.GetUA(c)
	url := "http://ip-api.com/json"
	if config.GetDevEnv(env) == config.Prod {
		ip = c.IP()
		url = fmt.Sprintf("%s/%s", url, c.IP())
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to retrieve the ip address")
	}

	var payload struct {
		City       string  `json:"city"`
		Country    string  `json:"country"`
		Query      string  `json:"query"`
		RegionName string  `json:"regionName"`
		Timezone   string  `json:"timezone"`
		Zip        string  `json:"zip"`
		Lat        float32 `json:"lat"`
		Lon        float32 `json:"lon"`
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("could not get ip address metadata")
	}
	if config.GetDevEnv(env) != config.Prod {
		ip = payload.Query
	}
	if ip == "" {
		return fmt.Errorf("failed parsing ip metadata")
	}

	refreshTokenD, err := refreshTokenS.Create(schemas.RefreshTokenMetadata{
		IPAddress:    ip,
		DeviceVendor: ua.Device.Vendor,
		DeviceModel:  ua.Device.Model,
		OSName:       ua.OS.Name,
		OSVersion:    ua.OS.Version,
		Country:      payload.Country,
		City:         payload.City,
		RegionName:   payload.RegionName,
		Timezone:     payload.Timezone,
		Zip:          payload.Zip,
		Lat:          payload.Lat,
		Lon:          payload.Lon,
	})
	if err != nil {
		return err
	}
	res, err = http.Get(fmt.Sprintf(
		"https://maps.googleapis.com/maps/api/staticmap?center=%s,%s&zoom=16&size=400x250&key=%s",
		fmt.Sprint(payload.Lat),
		fmt.Sprint(payload.Lon),
		env.GoogleMapsAPISecret,
	))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	_, err = conn.M.PutObject(
		context.Background(),
		"sessions",
		fmt.Sprintf("%s/%s", user.ID.String(), refreshTokenD.TokenUUID),
		res.Body,
		res.ContentLength,
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
		},
	)
	if err != nil {
		return err
	}

	accessTokenD, err := accessTokenS.Create(refreshTokenD.TokenUUID)
	if err != nil {
		return err
	}
	sessionTokenD, err := sessionTokenS.Create(*user)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    *accessTokenD.Token,
		Path:     "/",
		MaxAge:   env.AccessTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenD.Token,
		Path:     "/",
		MaxAge:   env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "session",
		Value:    *sessionTokenD.Token,
		Path:     "/",
		MaxAge:   env.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return nil
}

// GenerateOAuthCookie is a function that is used to generate oauth token to manage oauth related activites
func GenerateOAuthCookie(c *fiber.Ctx, conn *connect.Connector, env *config.Env, accessToken, provider string) error {
	oauthTokenS := token.OAuthToken{
		Conn:        conn,
		Env:         env,
		Provider:    provider,
		AccessToken: accessToken,
	}

	tokenDetails, err := oauthTokenS.Create()
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     "oauth_token",
		Value:    *tokenDetails.Token,
		Path:     "/",
		MaxAge:   env.OAuthTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: false,
		Domain:   "localhost",
	})

	return nil
}
