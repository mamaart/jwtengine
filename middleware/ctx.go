package middleware

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt"
)

const tokenContextKey = "token"

func ContextWithClaims(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenContextKey, tokenToNonStandardClaimsMap(token))
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

func tokenToNonStandardClaimsMap(token *jwt.Token) map[string]interface{} {
	myMap := make(map[string]interface{})
	for k, v := range token.Claims.(jwt.MapClaims) {
		if !isStandardClaim(k) {
			myMap[k] = v
		}
	}
	return myMap
}

func isStandardClaim(claim string) bool {
	switch claim {
	case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
		return true
	default:
		return false
	}
}
