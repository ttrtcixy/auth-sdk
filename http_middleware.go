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

type ctxKey string

const UserInfoKey ctxKey = "user_info"

func (ac *AuthClient) UserInfoFromContext(ctx context.Context) (*UserDTO, error) {
	val, ok := ctx.Value(UserInfoKey).(*UserDTO)
	if !ok {
		return nil, errors.New("user info not found in context")
	}
	return val, nil
}

var (
	headerMissing = []byte(`{"error": "authorization header is missing"}`)
	invalidFormat = []byte(`{"error": "invalid authorization format (Bearer expected)"}`)
	tokenExpired  = []byte(`{"error": "access token expired"}`)
	invalidToken  = []byte(`{"error": "invalid access token"}`)
)

func (ac *AuthClient) AuthMiddleware() func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			tokenString := r.Header.Get("Authorization")
			if tokenString == "" {
				ac.writeError(r.Context(), w, headerMissing)
				return
			}

			parts := strings.Split(tokenString, "Bearer")
			if len(parts) != 2 {
				ac.writeError(r.Context(), w, invalidFormat)
				return
			}

			accessToken := strings.TrimSpace(parts[1])
			if len(accessToken) < 1 {
				ac.writeError(r.Context(), w, invalidFormat)
				return
			}

			result, err := ac.validator.ParseAccessToken(r.Context(), accessToken)
			if err != nil {
				var msg = invalidToken
				if errors.Is(err, ErrAccessTokenExpired) {
					msg = tokenExpired
				} else {
					ac.log.LogAttrs(r.Context(), slog.LevelWarn, "suspicious token",
						slog.String("error", err.Error()),
						slog.String("remote_addr", r.RemoteAddr),
					)
				}
				ac.writeError(r.Context(), w, msg)
				return
			}

			userInfo := &UserDTO{
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

func (ac *AuthClient) writeError(ctx context.Context, w http.ResponseWriter, msg []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, err := w.Write(msg)
	if err != nil {
		ac.log.LogAttrs(ctx, slog.LevelError, "write error", slog.String("error", err.Error()))
	}
}
