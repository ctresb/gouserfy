package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type UserAuth struct {
	UserID               uuid.UUID       `json:"user_id" db:"user_id"`
	PasswordHash         string          `json:"-" db:"password_hash"`
	TwoFactorEnabled     bool            `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret      *string         `json:"-" db:"two_factor_secret"`
	TwoFactorBackupCodes json.RawMessage `json:"-" db:"two_factor_backup_codes"`
	PasswordChangedAt    *time.Time      `json:"password_changed_at,omitempty" db:"password_changed_at"`
	LastLoginAt          *time.Time      `json:"last_login_at,omitempty" db:"last_login_at"`
	LastLoginIP          *string         `json:"last_login_ip,omitempty" db:"last_login_ip"`
	FailedLoginAttempts  int             `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil          *time.Time      `json:"locked_until,omitempty" db:"locked_until"`
	AuthTokensRevokedAt  *time.Time      `json:"auth_tokens_revoked_at,omitempty" db:"auth_tokens_revoked_at"`
	WebauthnCredentials  json.RawMessage `json:"-" db:"webauthn_credentials"`
}
