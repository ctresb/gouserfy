-- +goose Up
CREATE TABLE user_oauth (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, provider),
    UNIQUE (provider, provider_id)
);

CREATE INDEX idx_user_oauth_provider ON user_oauth(provider, provider_id);

-- +goose Down
DROP TABLE IF EXISTS user_oauth;
