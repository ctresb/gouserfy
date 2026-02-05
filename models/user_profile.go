package models

import (
	"time"

	"github.com/google/uuid"
)

type UserProfile struct {
	UserID      uuid.UUID  `json:"user_id" db:"user_id"`
	DisplayName *string    `json:"display_name,omitempty" db:"display_name"`
	FirstName   *string    `json:"first_name,omitempty" db:"first_name"`
	LastName    *string    `json:"last_name,omitempty" db:"last_name"`
	Bio         *string    `json:"bio,omitempty" db:"bio"`
	AvatarURL   *string    `json:"avatar_url,omitempty" db:"avatar_url"`
	CoverURL    *string    `json:"cover_url,omitempty" db:"cover_url"`
	Location    *string    `json:"location,omitempty" db:"location"`
	Website     *string    `json:"website,omitempty" db:"website"`
	BirthDate   *time.Time `json:"birth_date,omitempty" db:"birth_date"`
	Gender      *string    `json:"gender,omitempty" db:"gender"`
	Pronouns    *string    `json:"pronouns,omitempty" db:"pronouns"`
}
