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
	Username         string     `gorm:"type:varchar(150);uniqueIndex;not null"`
	Email            string     `gorm:"type:varchar(255);uniqueIndex;default:null"`
	OAuthConnections []OAuth    `gorm:"foreignKey:UserID"`
	OTPMethod        []OTP      `gorm:"foreignKey:UserID"`
	TwoFactorEnabled bool       `gorm:"default:false"`
}
