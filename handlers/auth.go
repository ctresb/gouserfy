package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ctresb/gouserfy/services"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AuthHandler struct {
	auth *services.AuthService
}

func NewAuthHandler(auth *services.AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

func (h *AuthHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/register", h.Register)
	r.Post("/login", h.Login)
	r.Post("/login/2fa", h.Login2FA)
	r.Post("/refresh", h.RefreshToken)
	r.Post("/logout", h.Logout)
	r.Post("/logout/all", h.LogoutAll)
	r.Post("/verify-email", h.VerifyEmail)
	r.Post("/forgot-password", h.ForgotPassword)
	r.Post("/reset-password", h.ResetPassword)
	r.Post("/change-password", h.ChangePassword)
	r.Post("/2fa/enable", h.Enable2FA)
	r.Post("/2fa/confirm", h.Confirm2FA)
	r.Post("/2fa/disable", h.Disable2FA)
	return r
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Login2FARequest struct {
	UserID string `json:"user_id"`
	Code   string `json:"code"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type Enable2FAResponse struct {
	Secret      string   `json:"secret"`
	BackupCodes []string `json:"backup_codes"`
}

type Confirm2FARequest struct {
	Secret      string   `json:"secret"`
	Code        string   `json:"code"`
	BackupCodes []string `json:"backup_codes"`
}

type Disable2FARequest struct {
	Code string `json:"code"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, token, err := h.auth.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		if err == services.ErrUserExists {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"user":               user,
		"verification_token": token,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	ip := getIP(r)
	ua := r.UserAgent()

	tokens, user, err := h.auth.Login(r.Context(), req.Email, req.Password, ip, ua)
	if err != nil {
		if err == services.ErrTwoFactorRequired {
			writeJSON(w, http.StatusAccepted, map[string]interface{}{
				"requires_2fa": true,
				"user_id":      user.ID,
			})
			return
		}
		if err == services.ErrAccountLocked {
			writeError(w, http.StatusForbidden, "account locked")
			return
		}
		if err == services.ErrAccountInactive {
			writeError(w, http.StatusForbidden, "account not active")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tokens": tokens,
		"user":   user,
	})
}

func (h *AuthHandler) Login2FA(w http.ResponseWriter, r *http.Request) {
	var req Login2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	ip := getIP(r)
	ua := r.UserAgent()

	tokens, user, err := h.auth.LoginWith2FA(r.Context(), userID, req.Code, ip, ua)
	if err != nil {
		if err == services.ErrInvalid2FACode {
			writeError(w, http.StatusUnauthorized, "invalid 2fa code")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tokens": tokens,
		"user":   user,
	})
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	ip := getIP(r)
	ua := r.UserAgent()

	tokens, err := h.auth.RefreshTokens(r.Context(), req.RefreshToken, ip, ua)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	writeJSON(w, http.StatusOK, tokens)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	h.auth.Logout(r.Context(), req.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.auth.LogoutAll(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "all sessions logged out"})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.auth.VerifyEmail(r.Context(), req.Token); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "email verified"})
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	token, _ := h.auth.RequestPasswordReset(r.Context(), req.Email)

	response := map[string]string{"message": "if email exists, reset link sent"}
	if token != "" {
		response["reset_token"] = token
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.auth.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "password reset successful"})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.auth.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, "password change failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed"})
}

func (h *AuthHandler) Enable2FA(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	secret, backupCodes, err := h.auth.Enable2FA(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "2fa setup failed")
		return
	}

	writeJSON(w, http.StatusOK, Enable2FAResponse{
		Secret:      secret,
		BackupCodes: backupCodes,
	})
}

func (h *AuthHandler) Confirm2FA(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req Confirm2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.auth.Confirm2FA(r.Context(), userID, req.Secret, req.Code, req.BackupCodes); err != nil {
		if err == services.ErrInvalid2FACode {
			writeError(w, http.StatusBadRequest, "invalid code")
			return
		}
		writeError(w, http.StatusInternalServerError, "2fa confirmation failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "2fa enabled"})
}

func (h *AuthHandler) Disable2FA(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req Disable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.auth.Disable2FA(r.Context(), userID, req.Code); err != nil {
		if err == services.ErrInvalid2FACode {
			writeError(w, http.StatusBadRequest, "invalid code")
			return
		}
		writeError(w, http.StatusInternalServerError, "2fa disable failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "2fa disabled"})
}

func getIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
