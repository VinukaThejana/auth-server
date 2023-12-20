// Package connect is used to initialize connections to thrid party services
package connect

import (
	"github.com/gofiber/storage/redis"
	"github.com/minio/minio-go/v7"
	"gorm.io/gorm"
)

// Connector contains various connections to thrid party serivces
type Connector struct {
	DB         *gorm.DB
	Ratelimter *redis.Storage
	R          *Redis
	M          *minio.Client
}
