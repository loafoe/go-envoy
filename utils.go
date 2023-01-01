package envoy

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func GetJWTExpired(rawToken string) (*time.Time, error) {
	token, err := parseUnverified(rawToken)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid or missing claims")
	}
	unixTs, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid or missing 'exp' claim: %+v", claims)
	}
	tm := time.Unix(int64(unixTs), 0)
	return &tm, nil
}

func parseUnverified(rawToken string) (*jwt.Token, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(rawToken, jwt.MapClaims{})
	return token, err
}
