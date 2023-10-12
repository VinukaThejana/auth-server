package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuth is a struct that represents users oauth connections
type OAuth struct {
	ID         *uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	UserID     *uuid.UUID `gorm:"type:uuid"`
	CreatedAt  *time.Time `gorm:"not null;default:now()"`
	Provider   string
	ProviderID string `gorm:"type:varchar(255);not null"`
}
