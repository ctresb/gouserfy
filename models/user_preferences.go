package models

import (
	"encoding/json"

	"github.com/google/uuid"
)

type Theme string

const (
	ThemeLight  Theme = "light"
	ThemeDark   Theme = "dark"
	ThemeSystem Theme = "system"
)

type UserPreferences struct {
	UserID               uuid.UUID       `json:"user_id" db:"user_id"`
	Language             string          `json:"language" db:"language"`
	Timezone             string          `json:"timezone" db:"timezone"`
	Theme                Theme           `json:"theme" db:"theme"`
	NotificationSettings json.RawMessage `json:"notification_settings" db:"notification_settings"`
	PrivacySettings      json.RawMessage `json:"privacy_settings" db:"privacy_settings"`
	MarketingOptIn       bool            `json:"marketing_opt_in" db:"marketing_opt_in"`
}
