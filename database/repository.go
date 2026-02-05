package database

import (
	"context"
	"strings"
	"time"

	"github.com/ctresb/gouserfy/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, email string, passwordHash string) (*models.User, error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var user models.User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, status)
		VALUES (LOWER($1), 'inactive')
		RETURNING id, username, email, status, created_at, updated_at, deleted_at
	`, email).Scan(&user.ID, &user.Username, &user.Email, &user.Status, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO user_auth (user_id, password_hash) VALUES ($1, $2)`, user.ID, passwordHash)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO user_profiles (user_id) VALUES ($1)`, user.ID)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO user_preferences (user_id) VALUES ($1)`, user.ID)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO user_verification (user_id) VALUES ($1)`, user.ID)
	if err != nil {
		return nil, err
	}

	defaultRole, _ := r.GetRoleByName(ctx, "user")
	if defaultRole != nil {
		_, err = tx.Exec(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, user.ID, defaultRole.ID)
		if err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, status, created_at, updated_at, deleted_at
		FROM users WHERE id = $1 AND deleted_at IS NULL
	`, id).Scan(&user.ID, &user.Username, &user.Email, &user.Status, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, status, created_at, updated_at, deleted_at
		FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`, email).Scan(&user.ID, &user.Username, &user.Email, &user.Status, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, username, email, status, created_at, updated_at, deleted_at
		FROM users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL
	`, username).Scan(&user.ID, &user.Username, &user.Email, &user.Status, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (r *UserRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1
	`, id, status)
	return err
}

func (r *UserRepository) UpdateUsername(ctx context.Context, id uuid.UUID, username string) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE users SET username = LOWER($2), updated_at = NOW() WHERE id = $1
	`, id, username)
	return err
}

func (r *UserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE users SET status = 'deleted', deleted_at = NOW(), updated_at = NOW() WHERE id = $1
	`, id)
	return err
}

func (r *UserRepository) GetAuth(ctx context.Context, userID uuid.UUID) (*models.UserAuth, error) {
	var auth models.UserAuth
	err := r.db.Pool.QueryRow(ctx, `
		SELECT user_id, password_hash, two_factor_enabled, two_factor_secret, two_factor_backup_codes,
			   password_changed_at, last_login_at, last_login_ip, failed_login_attempts, locked_until,
			   auth_tokens_revoked_at, webauthn_credentials
		FROM user_auth WHERE user_id = $1
	`, userID).Scan(
		&auth.UserID, &auth.PasswordHash, &auth.TwoFactorEnabled, &auth.TwoFactorSecret,
		&auth.TwoFactorBackupCodes, &auth.PasswordChangedAt, &auth.LastLoginAt, &auth.LastLoginIP,
		&auth.FailedLoginAttempts, &auth.LockedUntil, &auth.AuthTokensRevokedAt, &auth.WebauthnCredentials,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &auth, err
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_auth SET password_hash = $2, password_changed_at = NOW(), failed_login_attempts = 0, locked_until = NULL
		WHERE user_id = $1
	`, userID, passwordHash)
	return err
}

func (r *UserRepository) RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip string) error {
	if success {
		_, err := r.db.Pool.Exec(ctx, `
			UPDATE user_auth SET last_login_at = NOW(), last_login_ip = $2, failed_login_attempts = 0, locked_until = NULL
			WHERE user_id = $1
		`, userID, ip)
		return err
	}
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_auth SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = $1
	`, userID)
	return err
}

func (r *UserRepository) LockAccount(ctx context.Context, userID uuid.UUID, until time.Time) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE user_auth SET locked_until = $2 WHERE user_id = $1`, userID, until)
	return err
}

func (r *UserRepository) RevokeAllTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE user_auth SET auth_tokens_revoked_at = NOW() WHERE user_id = $1`, userID)
	return err
}

func (r *UserRepository) GetProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error) {
	var profile models.UserProfile
	err := r.db.Pool.QueryRow(ctx, `
		SELECT user_id, display_name, first_name, last_name, bio, avatar_url, cover_url,
			   location, website, birth_date, gender, pronouns
		FROM user_profiles WHERE user_id = $1
	`, userID).Scan(
		&profile.UserID, &profile.DisplayName, &profile.FirstName, &profile.LastName,
		&profile.Bio, &profile.AvatarURL, &profile.CoverURL, &profile.Location,
		&profile.Website, &profile.BirthDate, &profile.Gender, &profile.Pronouns,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &profile, err
}

func (r *UserRepository) UpdateProfile(ctx context.Context, profile *models.UserProfile) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_profiles SET display_name = $2, first_name = $3, last_name = $4, bio = $5,
			   avatar_url = $6, cover_url = $7, location = $8, website = $9, birth_date = $10,
			   gender = $11, pronouns = $12
		WHERE user_id = $1
	`, profile.UserID, profile.DisplayName, profile.FirstName, profile.LastName, profile.Bio,
		profile.AvatarURL, profile.CoverURL, profile.Location, profile.Website, profile.BirthDate,
		profile.Gender, profile.Pronouns)
	return err
}

func (r *UserRepository) GetPreferences(ctx context.Context, userID uuid.UUID) (*models.UserPreferences, error) {
	var prefs models.UserPreferences
	err := r.db.Pool.QueryRow(ctx, `
		SELECT user_id, language, timezone, theme, notification_settings, privacy_settings, marketing_opt_in
		FROM user_preferences WHERE user_id = $1
	`, userID).Scan(
		&prefs.UserID, &prefs.Language, &prefs.Timezone, &prefs.Theme,
		&prefs.NotificationSettings, &prefs.PrivacySettings, &prefs.MarketingOptIn,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &prefs, err
}

func (r *UserRepository) UpdatePreferences(ctx context.Context, prefs *models.UserPreferences) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_preferences SET language = $2, timezone = $3, theme = $4, notification_settings = $5,
			   privacy_settings = $6, marketing_opt_in = $7
		WHERE user_id = $1
	`, prefs.UserID, prefs.Language, prefs.Timezone, prefs.Theme, prefs.NotificationSettings,
		prefs.PrivacySettings, prefs.MarketingOptIn)
	return err
}

func (r *UserRepository) GetVerification(ctx context.Context, userID uuid.UUID) (*models.UserVerification, error) {
	var v models.UserVerification
	err := r.db.Pool.QueryRow(ctx, `
		SELECT user_id, email_verified_at, phone_number, phone_verified_at FROM user_verification WHERE user_id = $1
	`, userID).Scan(&v.UserID, &v.EmailVerifiedAt, &v.PhoneNumber, &v.PhoneVerifiedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &v, err
}

func (r *UserRepository) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `UPDATE user_verification SET email_verified_at = NOW() WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `UPDATE users SET status = 'active', updated_at = NOW() WHERE id = $1 AND status = 'inactive'`, userID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *UserRepository) CreateToken(ctx context.Context, userID uuid.UUID, tokenType models.TokenType, tokenHash string, expiresAt time.Time, newEmail *string) (*models.UserToken, error) {
	var token models.UserToken
	err := r.db.Pool.QueryRow(ctx, `
		INSERT INTO user_tokens (user_id, token_type, token_hash, new_email, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, token_type, token_hash, new_email, expires_at, used_at
	`, userID, tokenType, tokenHash, newEmail, expiresAt).Scan(
		&token.ID, &token.UserID, &token.TokenType, &token.TokenHash, &token.NewEmail, &token.ExpiresAt, &token.UsedAt,
	)
	return &token, err
}

func (r *UserRepository) GetTokenByHash(ctx context.Context, tokenHash string, tokenType models.TokenType) (*models.UserToken, error) {
	var token models.UserToken
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, token_type, token_hash, new_email, expires_at, used_at
		FROM user_tokens WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > NOW()
	`, tokenHash, tokenType).Scan(
		&token.ID, &token.UserID, &token.TokenType, &token.TokenHash, &token.NewEmail, &token.ExpiresAt, &token.UsedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &token, err
}

func (r *UserRepository) UseToken(ctx context.Context, tokenID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE user_tokens SET used_at = NOW() WHERE id = $1`, tokenID)
	return err
}

func (r *UserRepository) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, created_at FROM roles WHERE LOWER(name) = LOWER($1)
	`, name).Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &role, err
}

func (r *UserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT r.id, r.name, r.description, r.created_at
		FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *UserRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID, grantedBy *uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, granted_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
	`, userID, roleID, grantedBy)
	return err
}

func (r *UserRepository) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	return err
}

func (r *UserRepository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time, userAgent, ip string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.Pool.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, token_hash, expires_at, created_at, revoked_at, user_agent, ip
	`, userID, tokenHash, expiresAt, userAgent, ip).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.CreatedAt, &token.RevokedAt, &token.UserAgent, &token.IP,
	)
	return &token, err
}

func (r *UserRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at, revoked_at, user_agent, ip
		FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.CreatedAt, &token.RevokedAt, &token.UserAgent, &token.IP,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &token, err
}

func (r *UserRepository) RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1`, tokenID)
	return err
}

func (r *UserRepository) RevokeUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func (r *UserRepository) CreateOAuth(ctx context.Context, oauth *models.UserOAuth) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO user_oauth (user_id, provider, provider_id, access_token, refresh_token, token_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, provider) DO UPDATE SET
			provider_id = EXCLUDED.provider_id, access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token, token_expires_at = EXCLUDED.token_expires_at, updated_at = NOW()
	`, oauth.UserID, oauth.Provider, oauth.ProviderID, oauth.AccessToken, oauth.RefreshToken, oauth.TokenExpiresAt)
	return err
}

func (r *UserRepository) GetOAuthByProvider(ctx context.Context, provider, providerID string) (*models.UserOAuth, error) {
	var oauth models.UserOAuth
	err := r.db.Pool.QueryRow(ctx, `
		SELECT user_id, provider, provider_id, access_token, refresh_token, token_expires_at, created_at, updated_at
		FROM user_oauth WHERE provider = $1 AND provider_id = $2
	`, strings.ToLower(provider), providerID).Scan(
		&oauth.UserID, &oauth.Provider, &oauth.ProviderID, &oauth.AccessToken, &oauth.RefreshToken,
		&oauth.TokenExpiresAt, &oauth.CreatedAt, &oauth.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &oauth, err
}

func (r *UserRepository) Enable2FA(ctx context.Context, userID uuid.UUID, secret string, backupCodes []byte) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_auth SET two_factor_enabled = TRUE, two_factor_secret = $2, two_factor_backup_codes = $3
		WHERE user_id = $1
	`, userID, secret, backupCodes)
	return err
}

func (r *UserRepository) Disable2FA(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_auth SET two_factor_enabled = FALSE, two_factor_secret = NULL, two_factor_backup_codes = NULL
		WHERE user_id = $1
	`, userID)
	return err
}
