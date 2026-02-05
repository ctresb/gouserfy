-- +goose Up
CREATE TYPE token_type AS ENUM ('email_verification', 'password_reset', 'email_change');

CREATE TABLE user_tokens (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_type token_type NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    new_email VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_user_tokens_hash ON user_tokens(token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_user_tokens_user ON user_tokens(user_id, token_type);

-- +goose Down
DROP TABLE IF EXISTS user_tokens;
DROP TYPE IF EXISTS token_type;
