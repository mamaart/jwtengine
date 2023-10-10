package httpware

import (
	"crypto"
	"fmt"
	"net/http"
	"strings"

	"github.com/mamaart/jwtengine/middleware"
	"github.com/mamaart/jwtengine/validator"
)

type Middleware struct {
	*validator.Validator
}

func NewMiddleware(publicKey crypto.PublicKey) (*Middleware, error) {
	validator, err := validator.NewValidator(publicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create validator: %w", err)
	}
	return &Middleware{validator}, nil
}

func (m *Middleware) HandleHTTP(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := GetBearerToken(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		token, err := m.GetToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("invalid token: %s", err)))
			return
		}
		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("invalid token"))
			return
		}

		h.ServeHTTP(w, r.WithContext(middleware.ContextWithClaims(r.Context(), token)))
	}
}

func GetBearerToken(r *http.Request) (string, error) {
	parts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(parts) < 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("missing or invalid authorization header")
	}
	return parts[1], nil
}
