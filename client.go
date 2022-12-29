package envoy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/golang-jwt/jwt/v4"
)

const (
	defaultEnlightenBase = "https://enlighten.enphaseenergy.com"
	defaultGatewayBase   = "https://envoy.local"
)

type Client struct {
	sync.Mutex

	enlightenBase string
	gatewayBase   string
	username      string
	password      string
	serial        string
	token         *jwt.Token

	sessionId string
	expiresAt *time.Time
	debug     bool
}

func getSessionId(token, gatewayBase string, debug bool) (string, *time.Time, error) {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Jar:       jar,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/check_jwt", gatewayBase), nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	requestResponse, requestError := client.Do(req)
	if requestError != nil {
		return "", nil, requestError
	}
	defer func() {
		_ = requestResponse.Body.Close()
	}()
	_, err = io.ReadAll(requestResponse.Body)
	if err != nil {
		return "", nil, err
	}
	for _, cookie := range requestResponse.Cookies() {
		if cookie.Name == "sessionId" {
			expiresAt := time.Now().Add(10 * time.Minute)
			if debug {
				slog.Debug("successfully retrieved sessionId", "sessionId", cookie.Value)
			}
			return cookie.Value, &expiresAt, nil // Success!
		}
	}
	if debug {
		slog.Debug("failed to retrieve sessionId")
	}
	return "", nil, fmt.Errorf("sessionId cookie not found")
}

func getLongLivedJWT(enlightenBase, username, password, serial string, debug bool) (*jwt.Token, error) {
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

	_, errLogin := client.PostForm(fmt.Sprintf("%s/login/login", enlightenBase), fieldsLogin)
	// Response error checking omitted, but what we needed was the cookie, which is now in the jar

	if errLogin != nil {
		return nil, errLogin
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/entrez-auth-token?serial_num=%s", enlightenBase, serial), nil)
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

	jwtToken := TokenResponse{}
	unmarshalError := json.Unmarshal(body, &jwtToken)

	if unmarshalError != nil {
		return nil, unmarshalError
	}

	token, err := jwt.Parse(jwtToken.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	if debug {
		slog.Debug("successfully retrieved JWT", "jwt", token.Raw)
	}
	return token, nil
}

func NewClient(username, password, serial string, opts ...OptionFunc) (*Client, error) {
	var err error
	client := &Client{
		enlightenBase: defaultEnlightenBase,
		gatewayBase:   defaultGatewayBase,
		username:      username,
		password:      password,
		serial:        serial,
	}

	for _, o := range opts {
		if err := o(client); err != nil {
			return nil, err
		}
	}
	if client.gatewayBase == "" {
		return nil, fmt.Errorf("invalid or missing envoy gatewayBase")
	}
	if client.enlightenBase == "" {
		return nil, fmt.Errorf("invalid or missing enlightenBase")
	}
	_, err = client.longLivedJWT()
	if err != nil {
		return nil, fmt.Errorf("error getting JWT: %w", err)
	}
	_, err = client.shortLivedSessionId()
	if err != nil {
		return nil, fmt.Errorf("error getting sessionId: %w", err)
	}
	return client, nil
}

func (c *Client) longLivedJWT() (string, error) {
	var err error

	c.Lock()
	defer c.Unlock()

	if c.token != nil && c.expiresAt != nil && c.expiresAt.Before(time.Now()) {
		return c.token.Raw, nil
	}
	if c.serial == "" {
		return "", fmt.Errorf("missing gateway serial")
	}

	token, err := getLongLivedJWT(c.enlightenBase, c.username, c.password, c.serial, c.debug)
	if err != nil {
		return "", fmt.Errorf("getting long lived token with credentials: %w", err)
	}
	c.token = token
	return c.token.Raw, nil
}

func (c *Client) Production() (*ProductionResponse, error) {
	var resp ProductionResponse

	sessionId, err := c.shortLivedSessionId()

	if err != nil {
		return nil, err
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Jar:       jar,
		Transport: tr,
	}
	cookie := &http.Cookie{
		Name:  "sessionId",
		Value: sessionId,
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/production.json?details=1", c.gatewayBase), nil)
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	requestResponse, requestError := client.Do(req)
	if requestError != nil {
		return nil, requestError
	}
	defer func() {
		_ = requestResponse.Body.Close()
	}()

	err = json.NewDecoder(requestResponse.Body).Decode(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) shortLivedSessionId() (string, error) {
	if c.expiresAt != nil && c.expiresAt.Before(time.Now()) {
		return c.sessionId, nil
	}

	rawToken, err := c.longLivedJWT()
	if err != nil {
		return "", err
	}
	c.Lock()
	defer c.Unlock()

	sessionId, expiresAt, err := getSessionId(rawToken, c.gatewayBase, c.debug)
	if err != nil {
		return "", err
	}
	c.sessionId = sessionId
	c.expiresAt = expiresAt
	return sessionId, nil
}
