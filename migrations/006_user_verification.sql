-- +goose Up
CREATE TABLE user_verification (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email_verified_at TIMESTAMPTZ,
    phone_number VARCHAR(20),
    phone_verified_at TIMESTAMPTZ
);

CREATE INDEX idx_user_verification_phone ON user_verification(phone_number) WHERE phone_number IS NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS user_verification;
