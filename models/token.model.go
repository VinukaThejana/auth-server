package models

import (
	"time"

	"github.com/google/uuid"
)

// Sessions is a model that represents the login sessions
type Sessions struct {
	ID           *uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	UserID       *uuid.UUID `gorm:"uuid"`
	LoginAt      time.Time  `gorm:"not null;default:now()"`
	IPAddress    string     `gorm:"default:null"`
	DeviceVendor string     `gorm:"default:null"`
	DeviceModel  string     `gorm:"default:null"`
	OSName       string     `gorm:"default:null"`
	OSVersion    string     `gorm:"default:null"`
	Country      string     `gorm:"default:null"`
	City         string     `gorm:"default:null"`
	RegionName   string     `gorm:"default:null"`
	Timezone     string     `gorm:"default:null"`
	Zip          string     `gorm:"default:null"`
	Lat          float32    `gorm:"default:null"`
	Lon          float32    `gorm:"default:null"`
	ExpiresAt    int64      `gorm:"not null"`
}
