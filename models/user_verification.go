package models

import (
	"time"

	"github.com/google/uuid"
)

type UserVerification struct {
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty" db:"email_verified_at"`
	PhoneNumber     *string    `json:"phone_number,omitempty" db:"phone_number"`
	PhoneVerifiedAt *time.Time `json:"phone_verified_at,omitempty" db:"phone_verified_at"`
}
