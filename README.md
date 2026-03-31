# auth-sdk

Go SDK for validating JWT access tokens through an auth gRPC service and protecting HTTP handlers with middleware.

[Russian](./README.ru.md)

## How it works

- `AuthClient` connects to the auth gRPC service and loads public RSA keys.
- `TokenValidator` parses JWT access tokens, validates required claims, and checks signatures by `kid`.
- Public keys are refreshed on demand with a short TTL and concurrency-safe single-flight updates.
- `AuthMiddleware()` validates `Authorization: Bearer <token>` and injects user info into request context.

## Usage

```go
package main

import (
	"log/slog"
	"net/http"
	"os"

	authsdk "github.com/ttrtcixy/auth-sdk"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	client, err := authsdk.NewAuthClient(logger, &authsdk.Config{
		Host: "127.0.0.1",
		Port: "50051",
	})
	if err != nil {
		panic(err)
	}
	defer client.Close(nil)

	mux := http.NewServeMux()
	mux.Handle("/profile", client.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := client.UserInfoFromContext(r.Context())
		if err != nil {
			http.Error(w, "user not found in context", http.StatusUnauthorized)
			return
		}

		_, _ = w.Write([]byte("hello, " + user.Username))
	})))

	if err := http.ListenAndServe(":8080", mux); err != nil {
		panic(err)
	}
}
```
