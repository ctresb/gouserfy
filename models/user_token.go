package models

import (
	"time"

	"github.com/google/uuid"
)

type TokenType string

const (
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypePasswordReset     TokenType = "password_reset"
	TokenTypeEmailChange       TokenType = "email_change"
)

type UserToken struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	TokenType TokenType  `json:"token_type" db:"token_type"`
	TokenHash string     `json:"-" db:"token_hash"`
	NewEmail  *string    `json:"new_email,omitempty" db:"new_email"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
}
