package authsdk

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

type UserDTO struct {
	ID       string
	Username string
	Email    string
	RoleID   string
}

type ContextKey string

const UserInfoKey ContextKey = "user_info"

func (ac *AuthClient) UserFromContext(ctx context.Context) (UserDTO, bool) {
	val, ok := ctx.Value(UserInfoKey).(UserDTO)
	return val, ok
}

func (ac *AuthClient) AuthMiddleware() func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json") // todo

			tokenString := r.Header.Get("Authorization")
			if tokenString == "" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error": "authorization header is missing"}`))
				return
			}

			parts := strings.Split(tokenString, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error": ""invalid authorization format (Bearer expected)""}`))
				return
			}

			accessToken := parts[1]

			result, err := ac.validator.ParseAccessToken(accessToken)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				if errors.Is(err, ErrAccessTokenExpired) {
					_, _ = w.Write([]byte(`{"error": "access token expired"}`))
					return
				}
				if errors.Is(err, ErrInvalidAccessToken) {
					_, _ = w.Write([]byte(`{"error": "invalid access token"}`))
					return
				}
				_, _ = w.Write([]byte(`{"error": "parse token error"}`))
				ac.log.LogAttrs(r.Context(), slog.LevelError, "AuthMiddleware error", slog.String("error", err.Error()))
				return
			}

			userInfo := UserDTO{
				ID:       result.UserID,
				Username: result.Username,
				Email:    result.Email,
				RoleID:   result.RoleId,
			}

			ctx := context.WithValue(r.Context(), UserInfoKey, userInfo)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//func writeError(w http.ResponseWriter, code int)
