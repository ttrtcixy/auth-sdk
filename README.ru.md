# auth-sdk

Go SDK для проверки JWT access token через auth gRPC сервис и защиты HTTP-обработчиков с помощью middleware.

## Как это работает

- `AuthClient` подключается к auth gRPC сервису и загружает публичные RSA-ключи.
- `TokenValidator` парсит JWT access token, проверяет обязательные claims и подпись по `kid`.
- Публичные ключи обновляются по требованию с коротким TTL и потокобезопасным single-flight обновлением.
- `AuthMiddleware()` проверяет `Authorization: Bearer <token>` и добавляет информацию о пользователе в context запроса.

## Пример использования

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
