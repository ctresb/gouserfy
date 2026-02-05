package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
	OAuth    OAuthConfig
	Security SecurityConfig
}

type ServerConfig struct {
	Host        string
	Port        int
	BaseURL     string
	Environment string
	CORSOrigins []string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
	MaxConns int
}

type AuthConfig struct {
	JWTSecret           string
	JWTExpiry           time.Duration
	RefreshTokenExpiry  time.Duration
	PasswordResetExpiry time.Duration
	EmailVerifyExpiry   time.Duration
}

type OAuthConfig struct {
	Enabled  bool
	Google   OAuthProvider
	GitHub   OAuthProvider
	Facebook OAuthProvider
}

type OAuthProvider struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type SecurityConfig struct {
	RateLimitRequests int
	RateLimitWindow   time.Duration
	MaxLoginAttempts  int
	LockoutDuration   time.Duration
	Argon2Memory      uint32
	Argon2Iterations  uint32
	Argon2Parallelism uint8
	Argon2SaltLength  uint32
	Argon2KeyLength   uint32
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:        getEnv("SERVER_HOST", "0.0.0.0"),
			Port:        getEnvInt("SERVER_PORT", 8080),
			BaseURL:     getEnv("BASE_URL", "http://localhost:8080"),
			Environment: getEnv("ENVIRONMENT", "development"),
			CORSOrigins: getEnvSlice("CORS_ORIGINS", []string{"http://localhost:3000"}),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "gouserfy"),
			Password: getEnv("DB_PASSWORD", "gouserfy"),
			Name:     getEnv("DB_NAME", "gouserfy"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
			MaxConns: getEnvInt("DB_MAX_CONNS", 25),
		},
		Auth: AuthConfig{
			JWTSecret:           getEnv("JWT_SECRET", ""),
			JWTExpiry:           getEnvDuration("JWT_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry:  getEnvDuration("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),
			PasswordResetExpiry: getEnvDuration("PASSWORD_RESET_EXPIRY", 1*time.Hour),
			EmailVerifyExpiry:   getEnvDuration("EMAIL_VERIFY_EXPIRY", 24*time.Hour),
		},
		OAuth: OAuthConfig{
			Enabled: getEnvBool("OAUTH_ENABLED", false),
			Google: OAuthProvider{
				Enabled:      getEnvBool("OAUTH_GOOGLE_ENABLED", false),
				ClientID:     getEnv("OAUTH_GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("OAUTH_GOOGLE_REDIRECT_URL", ""),
			},
			GitHub: OAuthProvider{
				Enabled:      getEnvBool("OAUTH_GITHUB_ENABLED", false),
				ClientID:     getEnv("OAUTH_GITHUB_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_GITHUB_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("OAUTH_GITHUB_REDIRECT_URL", ""),
			},
			Facebook: OAuthProvider{
				Enabled:      getEnvBool("OAUTH_FACEBOOK_ENABLED", false),
				ClientID:     getEnv("OAUTH_FACEBOOK_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_FACEBOOK_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("OAUTH_FACEBOOK_REDIRECT_URL", ""),
			},
		},
		Security: SecurityConfig{
			RateLimitRequests: getEnvInt("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:   getEnvDuration("RATE_LIMIT_WINDOW", 1*time.Minute),
			MaxLoginAttempts:  getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:   getEnvDuration("LOCKOUT_DURATION", 15*time.Minute),
			Argon2Memory:      uint32(getEnvInt("ARGON2_MEMORY", 65536)),
			Argon2Iterations:  uint32(getEnvInt("ARGON2_ITERATIONS", 3)),
			Argon2Parallelism: uint8(getEnvInt("ARGON2_PARALLELISM", 2)),
			Argon2SaltLength:  uint32(getEnvInt("ARGON2_SALT_LENGTH", 16)),
			Argon2KeyLength:   uint32(getEnvInt("ARGON2_KEY_LENGTH", 32)),
		},
	}
}

func (c *Config) DatabaseURL() string {
	return "postgres://" + c.Database.User + ":" + c.Database.Password +
		"@" + c.Database.Host + ":" + strconv.Itoa(c.Database.Port) +
		"/" + c.Database.Name + "?sslmode=" + c.Database.SSLMode
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
