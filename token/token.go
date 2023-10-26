// Package token is used to create, modify, delete and validate access, refresh and sessions tokens
package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/errors"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Details is a struct that contains the data that need to be used when creating tokens
type Details struct {
	Token     *string
	ExpiresIn *int64
	TokenUUID string
	UserID    string
}

// RefreshToken is a struct that is used to perform operations on refresh tokens
type RefreshToken struct {
	Conn   *connect.Connector
	Env    *config.Env
	UserID uuid.UUID
}

// Create a refresh token
func (r *RefreshToken) Create(metadata schemas.RefreshTokenMetadata) (tokenDetails *Details, err error) {
	now := time.Now().UTC()

	tokenUUID, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}

	tokenDetails = &Details{
		ExpiresIn: new(int64),
		Token:     new(string),
	}

	*tokenDetails.ExpiresIn = now.Add(r.Env.RefreshTokenExpires).Unix()
	tokenDetails.TokenUUID = tokenUUID.String()
	tokenDetails.UserID = r.UserID.String()

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(r.Env.RefreshTokenPrivateKey)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return nil, err
	}

	claims := make(jwt.MapClaims)
	claims["sub"] = r.UserID.String()
	claims["token_uuid"] = tokenDetails.TokenUUID
	claims["exp"] = *tokenDetails.ExpiresIn
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	*tokenDetails.Token, err = jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return nil, err
	}

	tokenVal, err := json.Marshal(schemas.RefreshTokenDetails{
		UserID:          r.UserID.String(),
		AccessTokenUUID: "",
	})
	if err != nil {
		return nil, err
	}

	err = r.Conn.DB.Create(&models.Sessions{
		ID:        &tokenUUID,
		UserID:    &r.UserID,
		IPAddress: metadata.IPAddress,
		Location:  metadata.Location,
		Device:    metadata.Device,
		LoginAt:   now,
		ExpiresAt: *tokenDetails.ExpiresIn,
	}).Error
	if err != nil {
		return nil, err
	}

	err = r.Conn.R.Session.Set(context.TODO(), tokenDetails.TokenUUID, string(tokenVal), time.Unix(*tokenDetails.ExpiresIn, 0).Sub(now)).Err()
	return tokenDetails, err
}

// Validate is a function that is used to validate the refresh token
func (r *RefreshToken) Validate(token string) (isValid bool, err error) {
	tokenDetails, metadata, err := validate(r.Conn, token, r.Env.RefreshTokenPublicKey, r.UserID.String())
	if err != nil {
		return false, err
	}
	if metadata == nil {
		return false, fmt.Errorf("failed to get refresh token details")
	}

	if tokenDetails.UserID != r.UserID.String() {
		return false, nil
	}

	now := time.Now().UTC().Unix()
	if *tokenDetails.ExpiresIn <= now {
		return false, nil
	}

	return true, nil
}

// AccessToken is a struct that is used to perform operations on access tokens
type AccessToken struct {
	Conn   *connect.Connector
	Env    *config.Env
	UserID uuid.UUID
}

// Create is a function that is used to create the access token
func (a *AccessToken) Create(refreshTokenUUID string) (tokenDetails *Details, err error) {
	now := time.Now().UTC()

	tokenUUID, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}

	tokenDetails = &Details{
		ExpiresIn: new(int64),
		Token:     new(string),
	}

	*tokenDetails.ExpiresIn = now.Add(a.Env.AccessTokenExpires).Unix()
	tokenDetails.TokenUUID = tokenUUID.String()
	tokenDetails.UserID = a.UserID.String()

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(a.Env.AccessTokenPrivateKey)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return nil, err
	}

	claims := make(jwt.MapClaims)
	claims["sub"] = a.UserID.String()
	claims["token_uuid"] = tokenDetails.TokenUUID
	claims["exp"] = *tokenDetails.ExpiresIn
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	*tokenDetails.Token, err = jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return nil, err
	}

	tokenVal, err := json.Marshal(schemas.RefreshTokenDetails{
		UserID:          a.UserID.String(),
		AccessTokenUUID: tokenDetails.TokenUUID,
	})
	if err != nil {
		return nil, err
	}

	ctx := context.TODO()

	ttl := a.Conn.R.Session.TTL(ctx, refreshTokenUUID).Val()
	if ttl.Seconds() < 0 {
		ttl = 0
	}
	err = a.Conn.R.Session.Set(ctx, refreshTokenUUID, string(tokenVal), ttl).Err()
	if err != nil {
		return nil, err
	}

	err = a.Conn.R.Session.Set(ctx, tokenDetails.TokenUUID, a.UserID.String(), time.Unix(*tokenDetails.ExpiresIn, 0).Sub(now)).Err()
	return tokenDetails, err
}

// Validate is a function that is used to validate the access token
func (a *AccessToken) Validate(token string) (isValid bool, err error) {
	tokenDetails, _, err := validate(a.Conn, token, a.Env.AccessTokenPublicKey, a.UserID.String())
	if err != nil {
		return false, err
	}

	if tokenDetails.UserID != a.UserID.String() {
		return false, nil
	}

	now := time.Now().UTC().Unix()
	if *tokenDetails.ExpiresIn <= now {
		return false, nil
	}

	return true, nil
}

// Delete is a function that is used to delete access and refresh tokens
func Delete(
	conn *connect.Connector,
	tokens struct {
		RefreshTokenUUIDStr string
		AccessTokenUUIDStr  string
	},
	env *config.Env,
	userID uuid.UUID,
) (err error) {
	refreshTokenUUID, err := uuid.Parse(tokens.RefreshTokenUUIDStr)
	if err != nil {
		return err
	}

	_, metadata, err := validate(conn, tokens.RefreshTokenUUIDStr, env.RefreshTokenPublicKey, userID.String())
	if err != nil {
		return err
	}
	_, _, err = validate(conn, tokens.AccessTokenUUIDStr, env.AccessTokenPublicKey, userID.String())
	if err != nil {
		return nil
	}

	ctx := context.TODO()
	pipe := conn.R.Session.Pipeline()

	if metadata != nil {
		metadata, ok := metadata.(schemas.RefreshTokenDetails)
		if ok {
			pipe.Del(ctx, metadata.AccessTokenUUID)
		}
	}

	pipe.Del(ctx, tokens.RefreshTokenUUIDStr)
	pipe.Del(ctx, tokens.AccessTokenUUIDStr)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return err
	}

	err = conn.DB.Delete(&models.Sessions{
		ID:     &refreshTokenUUID,
		UserID: &userID,
	}).Error
	return err
}

// DeleteExpired is a function that is used to delete expired session tokens
func DeleteExpired(conn *connect.Connector, userID uuid.UUID) {
	now := time.Now().UTC().Unix()

	var sessions []models.Sessions
	err := conn.DB.Where("user_id = ? AND expires_at <= ?", userID.String(), now).Find(&sessions).Error
	if err != nil {
		logger.ErrorWithMsg(
			err,
			"Failed to delete expired tokens",
		)
		return
	}

	if len(sessions) == 0 {
		return
	}

	err = conn.DB.Where("1 = 1").Delete(&sessions).Error
	if err != nil {
		logger.ErrorWithMsg(
			err,
			"Failed to delete expired tokens",
		)
		return
	}
}

func validate(conn *connect.Connector, token, publicKey, userID string) (tokenDetails *Details, metadata interface{}, err error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, nil, err
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method : %s", t.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return nil, nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, nil, fmt.Errorf("validate : invalid token")
	}

	tokenDetails = &Details{
		TokenUUID: fmt.Sprint(claims["token_uuid"]),
		UserID:    fmt.Sprint(claims["sub"]),
	}
	if tokenDetails.UserID != userID {
		return nil, nil, errors.ErrUnauthorized
	}

	val := conn.R.Session.Get(context.TODO(), tokenDetails.TokenUUID).Val()
	if val == "" {
		return nil, nil, errors.ErrUnauthorized
	}

	var valStr interface{}
	err = json.Unmarshal([]byte(val), &valStr)
	if err != nil {
		return tokenDetails, nil, nil
	}

	metadata, ok = valStr.(schemas.RefreshTokenDetails)
	if !ok {
		return tokenDetails, nil, nil
	}

	return tokenDetails, metadata, nil
}

// SessionToken is struct that manages the session token
type SessionToken struct {
	Conn *connect.Connector
	Env  *config.Env
}

// Create is a function that is used to create a new session token
func (s *SessionToken) Create(user models.User) (tokenDetails *Details, err error) {
	uid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tokenDetails = &Details{
		ExpiresIn: new(int64),
		Token:     new(string),
	}
	*tokenDetails.ExpiresIn = now.Add(s.Env.RefreshTokenExpires).Unix()
	tokenDetails.TokenUUID = uid.String()
	tokenDetails.UserID = user.ID.String()

	claims := make(jwt.MapClaims)
	claims["sub"] = user.ID
	claims["token_uuid"] = tokenDetails.TokenUUID
	claims["exp"] = tokenDetails.ExpiresIn
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["name"] = user.Name
	claims["username"] = user.Username
	claims["photo_url"] = user.PhotoURL
	claims["email"] = user.Email
	claims["two_factor_enabled"] = user.TwoFactorEnabled

	*tokenDetails.Token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.Env.SessionSecret))
	if err != nil {
		return nil, err
	}

	return tokenDetails, nil
}

// Validate is a function that is used to validate the session token
func (s *SessionToken) Validate(tokenStr string) (token *jwt.Token, err error) {
	token, err = jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected formating method")
		}

		return []byte(s.Env.SessionSecret), nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

// GetUserDetails is a function that is used to get the user details from the session token
func (s *SessionToken) GetUserDetails(token *jwt.Token) (user *schemas.User, err error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("cannot get details from the token")
	}

	twoFactorEnabled, err := strconv.ParseBool(claims["two_factor_enabled"].(string))
	if err != nil {
		return nil, err
	}

	return &schemas.User{
		ID:               claims["sub"].(string),
		Name:             claims["name"].(string),
		Username:         claims["username"].(string),
		Email:            claims["email"].(string),
		PhotoURL:         claims["photo_url"].(string),
		TwoFactorEnabled: twoFactorEnabled,
	}, nil
}
