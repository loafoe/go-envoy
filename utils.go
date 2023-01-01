package envoy

import (
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func getJWTExpired(rawToken string) (*time.Time, error) {
	token, err := parseUnverified(rawToken)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid or missing claims")
	}
	unixTs, err := strconv.ParseInt(claims["exp"].(string), 10, 64)
	if err != nil {
		return nil, err
	}
	tm := time.Unix(unixTs, 0)
	return &tm, nil
}

func parseUnverified(rawToken string) (*jwt.Token, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(rawToken, jwt.MapClaims{})
	return token, err
}
