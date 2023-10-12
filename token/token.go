// Package token is used to create, modify, delete and validate access, refresh and sessions tokens
package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/auth/schemas"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenDetails is a struct that contains the data that need to be used when creating tokens
type TokenDetails struct {
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
func (r *RefreshToken) Create(metadata schemas.RefreshTokenMetadata) (tokenDetails *TokenDetails, err error) {
	now := time.Now().UTC()

	tokenUUID, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}

	tokenDetails = &TokenDetails{
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
