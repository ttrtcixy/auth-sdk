package authsdk

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrAccessTokenExpired    = errors.New("access token is expired")
	ErrInvalidAccessToken    = errors.New("access token is invalid")
	ErrTokenSignatureInvalid = errors.New("access token invalid signature")
)

type KeyGetter interface {
	PublicKeys(ctx context.Context) (map[string]crypto.PublicKey, error)
}

type TokenValidator struct {
	keyGetter KeyGetter

	mu         sync.RWMutex
	publicKeys map[string]crypto.PublicKey
}

func NewTokenValidator(keyGetter KeyGetter) *TokenValidator {
	return &TokenValidator{
		keyGetter: keyGetter,
		mu:        sync.RWMutex{},
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

func (t *TokenValidator) ParseAccessToken(jwtToken string) (result *AccessTokenClaims, err error) {
	token, err := t.parse(jwtToken, &AccessTokenClaims{})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrAccessTokenExpired
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrInvalidAccessToken
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrInvalidAccessToken
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrTokenSignatureInvalid
		}
		return nil, err
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, ErrInvalidAccessToken
	}

	if claims.UserID == "" {
		return nil, ErrInvalidAccessToken
	}

	if claims.Username == "" {
		return nil, ErrInvalidAccessToken
	}

	if claims.Email == "" {
		return nil, ErrInvalidAccessToken
	}

	return claims, nil
}

func (t *TokenValidator) keyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("invalid access token")
		}

		return t.getKey(keyID)
	}
}

func (t *TokenValidator) getKey(keyID string) (crypto.PublicKey, error) {
	const op = "auth_sdk.getKey"
	if key, ok := t.keyByID(keyID); ok {
		return key, nil
	}

	// todo защита от постоянных запросов с невалидными токенами
	// todo только один запрос если сразу несколько вызывают
	keys, err := t.keyGetter.PublicKeys(nil)
	if err != nil {
		return nil, fmt.Errorf("%s -> %w", op, err)
	}

	t.mu.Lock()
	t.publicKeys = keys
	t.mu.Unlock()

	if key, ok := t.keyByID(keyID); ok {
		return key, nil
	}

	return nil, ErrInvalidAccessToken
}

func (t *TokenValidator) keyByID(keyID string) (crypto.PublicKey, bool) {
	t.mu.RLock()
	key, ok := t.publicKeys[keyID]
	t.mu.RUnlock()
	if ok {
		return key, true
	}

	return "", false
}

func (t *TokenValidator) parse(jwtToken string, claims jwt.Claims) (token *jwt.Token, err error) {
	token, err = jwt.ParseWithClaims(jwtToken, claims, t.keyFunc()) // todo другие проверки
	if err != nil {
		return nil, err
	}

	return token, nil
}
