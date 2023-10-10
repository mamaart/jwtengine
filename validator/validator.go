package validator

import (
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt"
)

type Validator struct {
	key crypto.PublicKey
}

func PublicKeyFromPem(pem []byte) (crypto.PublicKey, error) {
	return jwt.ParseEdPublicKeyFromPEM(pem)
}

func NewValidator(key crypto.PublicKey) (*Validator, error) {
	return &Validator{
		key: key,
	}, nil
}

func (v *Validator) GetToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return v.key, nil
		})
	if err != nil {
		return nil, fmt.Errorf("unable to parse token string: %w", err)
	}

	return token, nil
}
