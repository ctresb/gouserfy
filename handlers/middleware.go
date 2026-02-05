package handlers

import (
	"net/http"
	"strings"

	"github.com/ctresb/gouserfy/services"
)

type Middleware struct {
	auth *services.AuthService
}

func NewMiddleware(auth *services.AuthService) *Middleware {
	return &Middleware{auth: auth}
}

func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeError(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}

		claims, err := m.auth.ValidateToken(parts[1])
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := SetUserContext(r.Context(), claims.UserID, claims.Roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRoles, ok := r.Context().Value(rolesKey).([]string)
			if !ok {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}

			for _, required := range roles {
				for _, userRole := range userRoles {
					if userRole == required {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			writeError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			claims, err := m.auth.ValidateToken(parts[1])
			if err == nil {
				ctx := SetUserContext(r.Context(), claims.UserID, claims.Roles)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}
