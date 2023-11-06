package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents the user in the relational database
type User struct {
	ID               *uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	CreateAt         *time.Time `gorm:"not null;default:now()"`
	UpdatedAt        *time.Time `gorm:"not null;default:now()"`
	Name             string     `gorm:"type:varchar(200);not null"`
	Username         string     `gorm:"type:varchar(150);uniqueIndex;not null"`
	PhotoURL         string     `gorm:"type:varchar(255);not null"`
	Email            string     `gorm:"type:varchar(255);uniqueIndex;default:null"`
	Password         string     `gorm:"type:varchar(255);default:null"`
	PassKeys         []PassKeys `gorm:"foreignKey:UserID"`
	OAuthConnections []OAuth    `gorm:"foreignKey:UserID"`
	OTPMethod        []OTP      `gorm:"foreignKey:UserID"`
	Sessions         []Sessions `gorm:"foreignKey:UserID"`
	TwoFactorEnabled bool       `gorm:"default:false"`
	Verified         bool       `gorm:"default:false"`
}
