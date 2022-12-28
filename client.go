package envoy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
)

type Client struct {
	address  string
	username string
	password string
	serial   string
	token    *jwt.Token

	sessionId string
	*http.Client
}

type JWTToken struct {
	GenerationTime int    `json:"generation_time"`
	Token          string `json:"token"`
	ExpiresAt      int    `json:"expires_at"`
}

func getSessionId(token, address string) (string, error) {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Jar:       jar,
		Transport: tr,
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/auth/check_jwt", address), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	requestResponse, requestError := client.Do(req)
	if requestError != nil {
		return "", requestError
	}
	defer func() {
		_ = requestResponse.Body.Close()
	}()
	_, err := io.ReadAll(requestResponse.Body)
	if err != nil {
		return "", err
	}
	for _, cookie := range requestResponse.Cookies() {
		if cookie.Name == "sessionId" {
			return cookie.Value, nil // Success!
		}
	}
	return "", fmt.Errorf("sessionId cookie not found")
}

func getLongLivedJWT(username, password, serial string) (*jwt.Token, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("missing username or password when getting JWT")
	}
	if serial == "" {
		return nil, fmt.Errorf("missing serial number when getting JWT")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
	}

	// First, login using your username and password
	fieldsLogin := url.Values{"user[email]": {username}, "user[password]": {password}}

	_, errLogin := client.PostForm("https://enlighten.enphaseenergy.com/login/login", fieldsLogin)
	// Response error checking omitted, but what we needed was the cookie, which is now in the jar

	if errLogin != nil {
		return nil, errLogin
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://enlighten.enphaseenergy.com/entrez-auth-token?serial_num=%s", serial), nil)
	requestResponse, requestError := client.Do(req)
	if requestError != nil {
		return nil, requestError
	}
	defer func() {
		_ = requestResponse.Body.Close()
	}()

	body, err := io.ReadAll(requestResponse.Body)
	if err != nil {
		return nil, err
	}

	jwtToken := JWTToken{}
	unmarshalError := json.Unmarshal(body, &jwtToken)

	if unmarshalError != nil {
		return nil, unmarshalError
	}

	token, err := jwt.Parse(jwtToken.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	return token, nil
}

func NewClient(opts ...OptionFunc) (*Client, error) {
	var err error
	client := &Client{}

	for _, o := range opts {
		if err := o(client); err != nil {
			return nil, err
		}
	}
	if client.address == "" {
		return nil, fmt.Errorf("invalid or missing envoy address")
	}
	if client.token == nil {
		return nil, fmt.Errorf("invalid or missing credentials")
	}
	client.sessionId, err = getSessionId(client.token.Raw, client.address)
	if err != nil {
		return nil, err
	}
	return client, nil
}
