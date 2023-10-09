// Package connect is used to initialize connections to thrid party services
package connect

import "gorm.io/gorm"

// Connector contains various connections to thrid party serivces
type Connector struct {
	DB *gorm.DB
}
