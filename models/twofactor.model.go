package models

import "github.com/google/uuid"

// OTP is a struct that contains OTP based 2 step verification details
type OTP struct {
	ID            *uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	UserID        *uuid.UUID `gorm:"type:uuid"`
	Secret        string     `gorm:"unique;not null"`
	AuthURL       string     `gorm:"not null"`
	MemonicPhrase string     `gorm:"unique;null"`
	Verified      bool       `gorm:"default:false"`
}
