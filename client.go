package envoy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	defaultEnlightenBase = "https://enlighten.enphaseenergy.com"
	defaultGatewayBase   = "https://envoy.local"

	//Timeouts for client connections
	defaultTimeout             = 10 * time.Second
	defaultConnectTimeout      = 5 * time.Second // Timeout for establishing the connection
	defaultTLSHandshakeTimeout = 5 * time.Second // Timeout for the TLS handshake
	defaultKeepAlive           = 15 * time.Second
)

// HTTPClient is a wrapper around net/http.Client with improved defaults and error handling.
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates a new HTTPClient with sensible timeouts and keep-alive settings.
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   defaultConnectTimeout,
			KeepAlive: defaultKeepAlive,
		}).DialContext,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          1, // Adjust as needed for connection pooling
		IdleConnTimeout:       20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	jar, _ := cookiejar.New(nil)
	return &HTTPClient{
		client: &http.Client{
			Jar:       jar,
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

func (c *HTTPClient) ResetCookieJar() {
	jar, _ := cookiejar.New(nil)
	c.client.Jar = jar
}

type Client struct {
	sync.Mutex

	httpClient *HTTPClient

	enlightenBase string
	gatewayBase   string
	username      string
	password      string
	serial        string
	token         *jwt.Token
	jwtExpires    time.Time

	sessionId        string
	sessionCreatedAt time.Time
	sessionLastUsed  time.Time
	debug            bool
	jwtAtInit        bool
	notification     Notification
}

func getSessionId(token, gatewayBase string) (string, error) {
	client := NewHTTPClient(defaultTimeout)

	reqUri := fmt.Sprintf("%s/auth/check_jwt", gatewayBase)
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.client.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Warning: failed to close response body: %v", closeErr)
		}
	}()

	// Check the response status code.
	if resp.StatusCode != http.StatusOK {
		// Read the body for error details (but limit the amount read).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) // Read up to 1KB of the error body.
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, body)
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "sessionId" {
			return cookie.Value, nil // Success!
		}
	}
	return "", fmt.Errorf("sessionId cookie not found")
}

func getLongLivedJWT(enlightenBase, username, password, serial string) (*jwt.Token, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("missing username or password when getting JWT")
	}
	if serial == "" {
		return nil, fmt.Errorf("missing serial number when getting JWT")
	}

	client := NewHTTPClient(defaultTimeout)

	// First, login using your username and password
	fieldsLogin := url.Values{"user[email]": {username}, "user[password]": {password}}

	_, errLogin := client.client.PostForm(fmt.Sprintf("%s/login/login", enlightenBase), fieldsLogin)
	// Response error checking omitted, but what we needed was the cookie, which is now in the jar

	if errLogin != nil {
		return nil, errLogin
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/entrez-auth-token?serial_num=%s", enlightenBase, serial), nil)
	requestResponse, requestError := client.client.Do(req)
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

	token, _, err := new(jwt.Parser).ParseUnverified(jwtToken.Token, jwt.MapClaims{})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, err
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
		httpClient:    NewHTTPClient(defaultTimeout),
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
	_, err = client.shortLivedSessionId()
	if err != nil {
		return nil, fmt.Errorf("error getting sessionId: %w", err)
	}
	return client, nil
}

func (c *Client) InvalidateSession() {
	c.Lock()
	defer c.Unlock()

	c.sessionId = ""
}

func (c *Client) jwtExpired() bool {
	c.Lock()
	defer c.Unlock()

	if c.token == nil {
		return true
	}
	now := time.Now()

	return c.jwtExpires.Before(now)
}

func (c *Client) sessionExpired() bool {
	c.Lock()
	defer c.Unlock()

	now := time.Now()

	if c.sessionId == "" || c.sessionLastUsed.After(now.Add(30*time.Minute)) {
		return true
	}
	return false
}

func (c *Client) longLivedJWT() (string, error) {
	var err error

	if !c.jwtExpired() {
		return c.token.Raw, nil
	}
	if c.jwtAtInit && c.username == "" || c.password == "" {
		return "", fmt.Errorf("expired JWT and no username or password given")
	}

	c.Lock()
	defer c.Unlock()

	if c.serial == "" {
		return "", fmt.Errorf("missing gateway serial")
	}

	token, err := getLongLivedJWT(c.enlightenBase, c.username, c.password, c.serial)
	if err != nil {
		if c.notification != nil {
			c.notification.JWTError(err)
		}
		return "", fmt.Errorf("getting long lived token with credentials: %w", err)
	}
	expires, err := GetJWTExpired(token.Raw)
	if err != nil {
		return "", err
	}
	c.token = token
	c.jwtExpires = *expires
	if c.notification != nil {
		c.notification.JWTRefreshed(c.token.Raw)
	}
	return c.token.Raw, nil
}

func (c *Client) doRequest(uri string) (*[]byte, error) {
	sessionId, err := c.shortLivedSessionId()

	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:  "sessionId",
		Value: sessionId,
	}

	reqUri := fmt.Sprintf("%s%s", c.gatewayBase, uri)

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUri, nil)

	if err != nil {
		return nil, err
	}

	c.httpClient.ResetCookieJar()
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.client.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok && urlErr.Timeout() {
			return nil, fmt.Errorf("request timed out: %w", err)
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Warning: failed to close response body: %v", closeErr)
		}
	}()

	// Check the response status code.
	if resp.StatusCode != http.StatusOK {
		// Read the body for error details (but limit the amount read).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) // Read up to 1KB of the error body.
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return &body, err
}

func (c *Client) Batteries() (*[]Battery, error) {
	requestResponse, err := c.doRequest("/ivp/ensemble/inventory")

	if err != nil {
		return nil, err
	}

	var invresp InventoryResponse
	err = json.Unmarshal(*requestResponse, &invresp)
	if err != nil {
		return nil, err
	}
	for _, d := range invresp {
		if d.Type == "ENCHARGE" {
			return &d.Batteries, nil
		}
	}
	return &[]Battery{}, nil
}

func (c *Client) Inverters() (*[]Inverter, error) {
	var inverters []Inverter
	requestResponse, err := c.doRequest("/api/v1/production/inverters")

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(*requestResponse, &inverters)

	if err != nil {
		return nil, err
	}
	return &inverters, nil
}

func (c *Client) CommCheck() (*CommCheckResponse, error) {
	var commCheckResponse CommCheckResponse
	requestResponse, err := c.doRequest("/installer/pcu_comm_check")

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(*requestResponse, &commCheckResponse)
	if err != nil {
		return nil, err
	}
	return &commCheckResponse, nil
}

func (c *Client) Production() (*ProductionResponse, error) {
	var resp ProductionResponse
	requestResponse, err := c.doRequest("/production.json?details=1")

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(*requestResponse, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) shortLivedSessionId() (string, error) {
	if !c.sessionExpired() {
		c.sessionLastUsed = time.Now()
		if c.notification != nil {
			c.notification.SessionUsed(c.sessionId)
		}
		return c.sessionId, nil
	}

	rawToken, err := c.longLivedJWT()
	if err != nil {
		return "", err
	}
	c.Lock()
	defer c.Unlock()

	sessionId, err := getSessionId(rawToken, c.gatewayBase)
	if err != nil {
		if c.notification != nil {
			c.notification.SessionError(err)
		}
		return "", err
	}
	now := time.Now()
	c.sessionId = sessionId
	c.sessionCreatedAt = now
	c.sessionLastUsed = now
	if c.notification != nil {
		c.notification.SessionRefreshed(sessionId)
	}
	return sessionId, nil
}
