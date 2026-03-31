package authsdk

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

var (
	ErrAccessTokenExpired    = errors.New("access token is expired")
	ErrInvalidAccessToken    = errors.New("access token is invalid")
	ErrTokenSignatureInvalid = errors.New("access token invalid signature")
	ErrInvalidTokenUserInfo  = errors.New("access token invalid user info")
	ErrAlreadyUpdate         = errors.New("public keys already update")
)

type KeyGetter interface {
	PublicKeys(ctx context.Context) (map[string]crypto.PublicKey, error)
}

type TokenValidator struct {
	keyGetter KeyGetter

	lastUpdate time.Time
	refreshTTL time.Duration

	group      singleflight.Group
	mu         sync.RWMutex
	publicKeys map[string]crypto.PublicKey
}

func NewTokenValidator(keyGetter KeyGetter) *TokenValidator {
	return &TokenValidator{
		keyGetter:  keyGetter,
		mu:         sync.RWMutex{},
		group:      singleflight.Group{},
		refreshTTL: 10 * time.Second,
	}
}

type UserInfoClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	RoleId   string `json:"role_id"`
}

type AccessTokenClaims struct {
	UserInfoClaims
	jwt.RegisteredClaims
}

func (c *AccessTokenClaims) Validate() error {
	if c == nil {
		return errors.New("claims are nil")
	}

	if c.UserID == "" || c.RoleId == "" || c.Username == "" || c.Email == "" {
		return ErrInvalidTokenUserInfo
	}
	return nil
}

var _ jwt.ClaimsValidator = &AccessTokenClaims{}

func (t *TokenValidator) ParseAccessToken(ctx context.Context, jwtToken string) (result *AccessTokenClaims, err error) {
	token, err := jwt.ParseWithClaims(jwtToken, &AccessTokenClaims{}, t.keyFunc(ctx), jwt.WithExpirationRequired())
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenRequiredClaimMissing) || errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, ErrInvalidTokenUserInfo):
			return nil, ErrInvalidAccessToken
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrAccessTokenExpired
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrTokenSignatureInvalid
		default:
			slog.Log(ctx, slog.LevelError, "parser access tokens error", slog.String("error", err.Error()))
			return nil, err
		}
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, ErrInvalidAccessToken
	}

	return claims, nil
}

func (t *TokenValidator) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("invalid access token")
		}

		return t.getKey(ctx, keyID)
	}
}

func (t *TokenValidator) getKey(_ context.Context, keyID string) (crypto.PublicKey, error) {
	if key, ok := t.keyByID(keyID); ok {
		return key, nil
	}

	_, err, _ := t.group.Do("update_keys", func() (interface{}, error) {
		t.mu.RLock()
		lastUpdate := t.lastUpdate
		t.mu.RUnlock()

		if time.Since(lastUpdate) < t.refreshTTL {
			return nil, ErrAlreadyUpdate
		}

		keys, err := t.keyGetter.PublicKeys(context.Background())
		if err != nil {
			return nil, err
		}

		t.mu.Lock()
		t.lastUpdate = time.Now()
		t.publicKeys = keys
		t.mu.Unlock()

		return nil, nil
	})
	if err != nil {
		if errors.Is(err, ErrAlreadyUpdate) {
			return nil, ErrInvalidAccessToken
		}
		return nil, err
	}

	if key, ok := t.keyByID(keyID); ok {
		return key, nil
	}

	return nil, ErrInvalidAccessToken
}

func (t *TokenValidator) keyByID(keyID string) (crypto.PublicKey, bool) {
	t.mu.RLock()
	key, ok := t.publicKeys[keyID]
	t.mu.RUnlock()

	return key, ok
}
