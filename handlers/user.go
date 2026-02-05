package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ctresb/gouserfy/models"
	"github.com/ctresb/gouserfy/services"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type contextKey string

const userIDKey contextKey = "user_id"
const rolesKey contextKey = "roles"

type UserHandler struct {
	user *services.UserService
}

func NewUserHandler(user *services.UserService) *UserHandler {
	return &UserHandler{user: user}
}

func (h *UserHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/me", h.GetMe)
	r.Get("/{id}", h.GetUser)
	r.Delete("/me", h.DeleteMe)
	r.Get("/me/profile", h.GetMyProfile)
	r.Put("/me/profile", h.UpdateMyProfile)
	r.Get("/me/preferences", h.GetMyPreferences)
	r.Put("/me/preferences", h.UpdateMyPreferences)
	r.Get("/me/roles", h.GetMyRoles)
	r.Put("/me/username", h.UpdateMyUsername)
	return r
}

func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.user.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	user, err := h.user.GetByID(r.Context(), id)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (h *UserHandler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.user.Delete(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "account deleted"})
}

func (h *UserHandler) GetMyProfile(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	profile, err := h.user.GetProfile(r.Context(), userID)
	if err != nil || profile == nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

func (h *UserHandler) UpdateMyProfile(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var profile models.UserProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	profile.UserID = userID

	if err := h.user.UpdateProfile(r.Context(), &profile); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "profile updated"})
}

func (h *UserHandler) GetMyPreferences(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	prefs, err := h.user.GetPreferences(r.Context(), userID)
	if err != nil || prefs == nil {
		writeError(w, http.StatusNotFound, "preferences not found")
		return
	}

	writeJSON(w, http.StatusOK, prefs)
}

func (h *UserHandler) UpdateMyPreferences(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var prefs models.UserPreferences
	if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	prefs.UserID = userID

	if err := h.user.UpdatePreferences(r.Context(), &prefs); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "preferences updated"})
}

func (h *UserHandler) GetMyRoles(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	roles, err := h.user.GetRoles(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get roles")
		return
	}

	writeJSON(w, http.StatusOK, roles)
}

type UpdateUsernameRequest struct {
	Username string `json:"username"`
}

func (h *UserHandler) UpdateMyUsername(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req UpdateUsernameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.user.UpdateUsername(r.Context(), userID, req.Username); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "username updated"})
}

func getUserID(r *http.Request) uuid.UUID {
	if id, ok := r.Context().Value(userIDKey).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

func SetUserContext(ctx context.Context, userID uuid.UUID, roles []string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, rolesKey, roles)
	return ctx
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
