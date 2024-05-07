package middleware

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/mamaart/jwtengine/issuer"
)

const tokenContextKey = "token"

func ContextWithClaims(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenContextKey, issuer.ExtractClaims(token))
}

func ContextGetClaims(ctx context.Context) (map[string]interface{}, error) {
	val := ctx.Value(tokenContextKey)
	if val == nil {
		return nil, errors.New("no token in context")
	}

	t, ok := val.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected token type in context")
	}
	return t, nil
}
