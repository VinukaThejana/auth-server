package models

import "github.com/google/uuid"

// PassKeys is a struct representing the passkeys table in the relational database
type PassKeys struct {
	PassKeyID string     `gorm:"primary_key"`
	UserID    *uuid.UUID `gorm:"type:uuid;primary_key"`
	PublicKey string     `gorm:"unique;not null"`
}
