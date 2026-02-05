package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/ctresb/gouserfy/config"
	"github.com/ctresb/gouserfy/database"
	"github.com/ctresb/gouserfy/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked")
	ErrAccountInactive    = errors.New("account not active")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrTwoFactorRequired  = errors.New("2fa required")
	ErrInvalid2FACode     = errors.New("invalid 2fa code")
)

type AuthService struct {
	repo   *database.UserRepository
	config *config.Config
}

func NewAuthService(repo *database.UserRepository, cfg *config.Config) *AuthService {
	return &AuthService{repo: repo, config: cfg}
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	Roles  []string  `json:"roles"`
	jwt.RegisteredClaims
}

func (s *AuthService) Register(ctx context.Context, email, password string) (*models.User, string, error) {
	existing, _ := s.repo.GetByEmail(ctx, email)
	if existing != nil {
		return nil, "", ErrUserExists
	}

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return nil, "", err
	}

	user, err := s.repo.Create(ctx, email, hash)
	if err != nil {
		return nil, "", err
	}

	token, tokenHash := s.generateToken()
	_, err = s.repo.CreateToken(ctx, user.ID, models.TokenTypeEmailVerification, tokenHash, time.Now().Add(s.config.Auth.EmailVerifyExpiry), nil)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *AuthService) Login(ctx context.Context, email, password, ip, userAgent string) (*TokenPair, *models.User, error) {
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, nil, ErrInvalidCredentials
	}

	auth, err := s.repo.GetAuth(ctx, user.ID)
	if err != nil || auth == nil {
		return nil, nil, ErrInvalidCredentials
	}

	if auth.LockedUntil != nil && auth.LockedUntil.After(time.Now()) {
		return nil, nil, ErrAccountLocked
	}

	match, err := argon2id.ComparePasswordAndHash(password, auth.PasswordHash)
	if err != nil || !match {
		s.repo.RecordLoginAttempt(ctx, user.ID, false, ip)
		if auth.FailedLoginAttempts+1 >= s.config.Security.MaxLoginAttempts {
			s.repo.LockAccount(ctx, user.ID, time.Now().Add(s.config.Security.LockoutDuration))
		}
		return nil, nil, ErrInvalidCredentials
	}

	if user.Status != models.UserStatusActive {
		return nil, nil, ErrAccountInactive
	}

	if auth.TwoFactorEnabled {
		return nil, user, ErrTwoFactorRequired
	}

	return s.completeLogin(ctx, user, auth, ip, userAgent)
}

func (s *AuthService) LoginWith2FA(ctx context.Context, userID uuid.UUID, code, ip, userAgent string) (*TokenPair, *models.User, error) {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, nil, ErrInvalidCredentials
	}

	auth, err := s.repo.GetAuth(ctx, userID)
	if err != nil || auth == nil || !auth.TwoFactorEnabled {
		return nil, nil, ErrInvalidCredentials
	}

	if auth.TwoFactorSecret == nil {
		return nil, nil, ErrInvalidCredentials
	}

	valid := totp.Validate(code, *auth.TwoFactorSecret)
	if !valid {
		return nil, nil, ErrInvalid2FACode
	}

	return s.completeLogin(ctx, user, auth, ip, userAgent)
}

func (s *AuthService) completeLogin(ctx context.Context, user *models.User, auth *models.UserAuth, ip, userAgent string) (*TokenPair, *models.User, error) {
	s.repo.RecordLoginAttempt(ctx, user.ID, true, ip)

	roles, _ := s.repo.GetUserRoles(ctx, user.ID)
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}

	accessToken, expiresAt, err := s.generateJWT(user.ID, roleNames, auth.AuthTokensRevokedAt)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, refreshHash := s.generateToken()
	_, err = s.repo.CreateRefreshToken(ctx, user.ID, refreshHash, time.Now().Add(s.config.Auth.RefreshTokenExpiry), userAgent, ip)
	if err != nil {
		return nil, nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, user, nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken, ip, userAgent string) (*TokenPair, error) {
	hash := hashToken(refreshToken)
	token, err := s.repo.GetRefreshToken(ctx, hash)
	if err != nil || token == nil {
		return nil, ErrInvalidToken
	}

	user, err := s.repo.GetByID(ctx, token.UserID)
	if err != nil || user == nil || user.Status != models.UserStatusActive {
		return nil, ErrInvalidToken
	}

	auth, _ := s.repo.GetAuth(ctx, user.ID)
	if auth != nil && auth.AuthTokensRevokedAt != nil && token.CreatedAt.Before(*auth.AuthTokensRevokedAt) {
		s.repo.RevokeRefreshToken(ctx, token.ID)
		return nil, ErrInvalidToken
	}

	s.repo.RevokeRefreshToken(ctx, token.ID)

	roles, _ := s.repo.GetUserRoles(ctx, user.ID)
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}

	var revokedAt *time.Time
	if auth != nil {
		revokedAt = auth.AuthTokensRevokedAt
	}

	accessToken, expiresAt, err := s.generateJWT(user.ID, roleNames, revokedAt)
	if err != nil {
		return nil, err
	}

	newRefreshToken, newRefreshHash := s.generateToken()
	_, err = s.repo.CreateRefreshToken(ctx, user.ID, newRefreshHash, time.Now().Add(s.config.Auth.RefreshTokenExpiry), userAgent, ip)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := hashToken(refreshToken)
	token, err := s.repo.GetRefreshToken(ctx, hash)
	if err != nil || token == nil {
		return nil
	}
	return s.repo.RevokeRefreshToken(ctx, token.ID)
}

func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.RevokeUserRefreshTokens(ctx, userID); err != nil {
		return err
	}
	return s.repo.RevokeAllTokens(ctx, userID)
}

func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	hash := hashToken(token)
	userToken, err := s.repo.GetTokenByHash(ctx, hash, models.TokenTypeEmailVerification)
	if err != nil || userToken == nil {
		return ErrInvalidToken
	}

	if err := s.repo.VerifyEmail(ctx, userToken.UserID); err != nil {
		return err
	}

	return s.repo.UseToken(ctx, userToken.ID)
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return "", nil
	}

	token, tokenHash := s.generateToken()
	_, err = s.repo.CreateToken(ctx, user.ID, models.TokenTypePasswordReset, tokenHash, time.Now().Add(s.config.Auth.PasswordResetExpiry), nil)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	hash := hashToken(token)
	userToken, err := s.repo.GetTokenByHash(ctx, hash, models.TokenTypePasswordReset)
	if err != nil || userToken == nil {
		return ErrInvalidToken
	}

	passwordHash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return err
	}

	if err := s.repo.UpdatePassword(ctx, userToken.UserID, passwordHash); err != nil {
		return err
	}

	s.repo.RevokeUserRefreshTokens(ctx, userToken.UserID)
	return s.repo.UseToken(ctx, userToken.ID)
}

func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	auth, err := s.repo.GetAuth(ctx, userID)
	if err != nil || auth == nil {
		return ErrInvalidCredentials
	}

	match, err := argon2id.ComparePasswordAndHash(oldPassword, auth.PasswordHash)
	if err != nil || !match {
		return ErrInvalidCredentials
	}

	passwordHash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return err
	}

	return s.repo.UpdatePassword(ctx, userID, passwordHash)
}

func (s *AuthService) Enable2FA(ctx context.Context, userID uuid.UUID) (string, []string, error) {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return "", nil, ErrInvalidCredentials
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Gouserfy",
		AccountName: user.Email,
	})
	if err != nil {
		return "", nil, err
	}

	backupCodes := make([]string, 10)
	for i := range backupCodes {
		b := make([]byte, 4)
		rand.Read(b)
		backupCodes[i] = hex.EncodeToString(b)
	}

	return key.Secret(), backupCodes, nil
}

func (s *AuthService) Confirm2FA(ctx context.Context, userID uuid.UUID, secret, code string, backupCodes []string) error {
	valid := totp.Validate(code, secret)
	if !valid {
		return ErrInvalid2FACode
	}

	hashedCodes := make([]string, len(backupCodes))
	for i, c := range backupCodes {
		hashedCodes[i] = hashToken(c)
	}

	return s.repo.Enable2FA(ctx, userID, secret, []byte(`"`+string(hashedCodes[0])+`"`))
}

func (s *AuthService) Disable2FA(ctx context.Context, userID uuid.UUID, code string) error {
	auth, err := s.repo.GetAuth(ctx, userID)
	if err != nil || auth == nil || !auth.TwoFactorEnabled || auth.TwoFactorSecret == nil {
		return ErrInvalidCredentials
	}

	valid := totp.Validate(code, *auth.TwoFactorSecret)
	if !valid {
		return ErrInvalid2FACode
	}

	return s.repo.Disable2FA(ctx, userID)
}

func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.Auth.JWTSecret), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (s *AuthService) generateJWT(userID uuid.UUID, roles []string, revokedAt *time.Time) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.config.Auth.JWTExpiry)
	issuedAt := time.Now()

	if revokedAt != nil && issuedAt.Before(*revokedAt) {
		issuedAt = revokedAt.Add(time.Second)
	}

	claims := &Claims{
		UserID: userID,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			Issuer:    "gouserfy",
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.Auth.JWTSecret))
	return tokenString, expiresAt, err
}

func (s *AuthService) generateToken() (string, string) {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	return token, hashToken(token)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
