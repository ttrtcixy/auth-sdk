package authsdk

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	pb "github.com/ttrtcixy/auth-protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/emptypb"
)

var ErrClientNotInitialized = errors.New("client not initialized")
var ErrServerUnavailable = errors.New("grpc auth server unavailable")

type Config struct {
	Host    string `env:"GRPC_HOST"`
	Port    string `env:"GRPC_PORT"`
	Network string `env:"GRPC_NETWORK"`
}

type AuthClient struct {
	log *slog.Logger
	cfg *Config

	validator *TokenValidator

	conn   *grpc.ClientConn
	client pb.AuthClient

	reconnecting atomic.Bool
	mu           sync.Mutex
}

func NewAuthClient(log *slog.Logger, cfg *Config) (*AuthClient, error) {
	const op = "grpcauth.NewAuthClient"

	client := &AuthClient{
		log: log,
		cfg: cfg,
	}

	if err := client.connect(); err != nil {
		return nil, err
	}

	client.validator = NewTokenValidator(client)

	return client, nil
}

func (ac *AuthClient) connect() (err error) {
	const op = "grpcauth.connect"
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.conn != nil {
		if closeErr := ac.conn.Close(); closeErr != nil {
			ac.log.Error("%s: closing connection err: %w", op, err)
		}
	}

	// todo use config
	opts := []grpc.DialOption{
		// security
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// connection params
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  3 * time.Second,
				Multiplier: 1.6,
				MaxDelay:   30 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		// keepalive params
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 5 * time.Second}),
		// grpc request retry
		grpc.WithDefaultServiceConfig(`{
			"retryPolicy": {
				"maxAttempts": 4,       
				"initialBackoff": "0.1s", 
				"maxBackoff": "1s",    
				"backoffMultiplier": 2,
				"retryableStatusCodes": ["UNAVAILABLE"]
			}
		}`),
	}

	// todo add ping
	if ac.conn, err = grpc.NewClient(fmt.Sprintf("%s:%s", ac.cfg.Host, ac.cfg.Port), opts...); err != nil {
		return err
	}

	ac.client = pb.NewAuthClient(ac.conn)
	return nil
}

func (ac *AuthClient) getClient() (pb.AuthClient, error) {
	const op = "grpcauth.getClient"

	if ac.client == nil {
		return nil, ErrClientNotInitialized
	}

	if ac.conn.GetState() == connectivity.Shutdown {
		if ac.reconnecting.CompareAndSwap(false, true) {
			go ac.reconnect(context.Background())
		}
		return nil, ErrServerUnavailable
	}

	return ac.client, nil
}

func (ac *AuthClient) reconnect(ctx context.Context) {
	const op = "grpcauth.reconnect"
	defer ac.reconnecting.Store(false)

	ac.log.Error("%s: grpc auth server is not available, reconnection started", op)
	var recAttempts int
	for {
		select {
		case <-ctx.Done():
			ac.log.Info("%s: server reconnection stopped", op)
			return
		default:
			if err := ac.connect(); err != nil {
				recAttempts++
				ac.log.Error(
					"%s: grpc auth server is not available, reconnection attempt %d, err: %w",
					op,
					recAttempts,
					err,
				)
				continue
			}

			if ac.conn.GetState() == connectivity.Ready {
				ac.log.Info("%s: grpc auth server reconnected, reconnection attempt %d", op, recAttempts)
				return
			}
		}
	}
}

func (ac *AuthClient) PublicKeys(ctx context.Context) (map[string]crypto.PublicKey, error) {
	const op = "grpcauth.PublicKeys"

	client, err := ac.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.PublicKeys(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	respKeys := resp.GetPublicKeys()
	if len(respKeys) < 0 {
		return nil, fmt.Errorf("%s - bad request, no public keys", op)
	}

	keys := make(map[string]crypto.PublicKey)

	for k, v := range respKeys {
		if k == "" || len(v) == 0 {
			return nil, fmt.Errorf("%s - bad request, invalid public keys", op)
		}

		key, err := jwt.ParseRSAPublicKeyFromPEM(v)
		if err != nil {
			return nil, fmt.Errorf("%s - bad request, parse key error -> %w", op, err)
		}

		keys[k] = key
	}

	return keys, nil
}

// todo test with error
// todo могут быть ошибки если начнется реконект а мы закрываем соединение
func (ac *AuthClient) Close(_ context.Context) error {
	const op = "grpcauth.close"

	if err := ac.conn.Close(); err != nil {
		return fmt.Errorf("%s -> %w", op, err)
	}

	return nil
}
