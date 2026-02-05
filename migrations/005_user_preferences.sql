-- +goose Up
CREATE TYPE theme_type AS ENUM ('light', 'dark', 'system');

CREATE TABLE user_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    language VARCHAR(10) NOT NULL DEFAULT 'en-US',
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    theme theme_type NOT NULL DEFAULT 'system',
    notification_settings JSONB NOT NULL DEFAULT '{}',
    privacy_settings JSONB NOT NULL DEFAULT '{}',
    marketing_opt_in BOOLEAN NOT NULL DEFAULT FALSE
);

-- +goose Down
DROP TABLE IF EXISTS user_preferences;
DROP TYPE IF EXISTS theme_type;
