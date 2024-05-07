package issuer

import (
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/mamaart/jwtengine/models"
	"github.com/mamaart/jwtengine/validator"
)

type Claims interface {
	AccessClaimsAsMap() map[string]interface{}
	RefreshClaimsAsMap() map[string]interface{}
}

type RefreshClaimValidator[C Claims] interface {
	Validate(map[string]interface{}) (C, error)
}

type Issuer[C Claims] struct {
	refreshClaimValidator RefreshClaimValidator[C]
	access                *keys
	refresh               *keys
	validator             *validator.Validator
}

func newIssuer[C Claims](
	access, refresh *keys,
	refreshClaimValidator RefreshClaimValidator[C],
) (*Issuer[C], error) {
	validator, err := validator.NewValidator(refresh.public)
	if err != nil {
		return nil, fmt.Errorf("failed to generate validator for refresh tokens: %s", err)
	}

	return &Issuer[C]{
		refreshClaimValidator: refreshClaimValidator,
		access:                access,
		refresh:               refresh,
		validator:             validator,
	}, nil
}

func NewIssuerFromPrivateKeys[C Claims](
	accessPK crypto.PrivateKey,
	refreshPK crypto.PrivateKey,
	refreshClaimValidator RefreshClaimValidator[C],
) (*Issuer[C], error) {
	access, err := fromPrivateKey(accessPK)
	if err != nil {
		return nil, err
	}
	refresh, err := fromPrivateKey(refreshPK)
	if err != nil {
		return nil, fmt.Errorf("failed generating private key for refreshtoken issuer: %s", err)
	}
	return newIssuer(access, refresh, refreshClaimValidator)
}

func NewIssuer[C Claims](refreshClaimValidator RefreshClaimValidator[C]) (*Issuer[C], error) {
	access, err := keygen()
	if err != nil {
		return nil, err
	}
	refresh, err := keygen()
	if err != nil {
		return nil, fmt.Errorf("failed generating private key for refreshtoken issuer: %s", err)
	}
	return newIssuer(access, refresh, refreshClaimValidator)
}

func (i *Issuer[C]) PublicKeyRAW() crypto.PublicKey {
	return i.access.public
}

func (i *Issuer[C]) PublicKeyPEM() ([]byte, error) {
	return i.access.PublicKeyPEM()
}

func (i *Issuer[C]) Refresh(refreshToken string) (tokens *models.Tokens, err error) {
	token, err := i.validator.GetToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("token not a valid format")
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, err := i.refreshClaimValidator.Validate(TokenToNonStandardClaimsMap(token))
	if err != nil {
		return nil, fmt.Errorf("non standard claims failed validation: %s", err)
	}

	return i.IssueTokens(claims)
}

func (i *Issuer[C]) IssueTokens(claims C) (tokens *models.Tokens, err error) {
	accessToken, err := i.issueAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed issuing access token: %s", err)
	}

	refreshToken, err := i.issueRefreshToken("this should be modular", claims)
	if err != nil {
		return nil, fmt.Errorf("failed issuing refresh token: %s", err)
	}

	return &models.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (i *Issuer[C]) issueAccessToken(claims C) (string, error) {
	now := time.Now().Add(-time.Minute)
	c := jwt.MapClaims{
		// standardized claims
		"aud": "api",
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"iss": "http://localhost:8081",
	}

	// other claims
	for k, v := range claims.AccessClaimsAsMap() {
		if !isStandardClaim(k) {
			c[k] = v
		}
	}

	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, c)
	tokenString, err := token.SignedString(i.access.private)
	if err != nil {
		return "", fmt.Errorf("unable to sign token: %w", err)
	}

	return tokenString, nil
}

func (i *Issuer[C]) issueRefreshToken(user string, claims C) (string, error) {
	now := time.Now().Add(-time.Minute)
	c := jwt.MapClaims{
		"exp": now.Add(time.Hour * 24 * 14).Unix(),
		"iss": "http://localhost:8081",
	}

	// other claims
	for k, v := range claims.RefreshClaimsAsMap() {
		if !isStandardClaim(k) {
			c[k] = v
		}
	}

	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, c)

	tokenString, err := token.SignedString(i.refresh.private)
	if err != nil {
		return "", fmt.Errorf("unable to sign token: %w", err)
	}

	return tokenString, nil
}

func TokenToNonStandardClaimsMap(token *jwt.Token) map[string]interface{} {
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
