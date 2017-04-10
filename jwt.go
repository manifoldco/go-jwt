package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type jwtContents struct {
	CustomClaims interface{} `json:"custom_claims"`
	jwt.StandardClaims
}

// New returns a signed JWT string for the given claims
func New(signingKey string, claims interface{}, expireDuration *time.Duration) (string, jwt.StandardClaims, error) {
	var standardClaims jwt.StandardClaims
	if expireDuration != nil {
		standardClaims = jwt.StandardClaims{
			ExpiresAt: time.Now().UTC().Add(*expireDuration).Unix(),
		}
	}
	contents := jwtContents{
		CustomClaims:   claims,
		StandardClaims: standardClaims,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, contents)
	str, err := token.SignedString([]byte(signingKey))
	return str, standardClaims, err
}

// Read returns the interface of custom claims from within the token
func Read(signingKey, jwtString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, invalidJwtError("claim validation failed")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if custom, ok := claims["custom_claims"].(map[string]interface{}); ok {
			return custom, nil
		}
	}
	return nil, invalidJwtError("could not read claims")
}

func invalidJwtError(err string) error {
	return fmt.Errorf("invalid jwt: %s", err)
}
