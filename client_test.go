package envoy_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/loafoe/go-envoy"
)

var (
	muxEnlighten    *http.ServeMux
	enlightenServer *httptest.Server

	muxGateway    *http.ServeMux
	gatewayServer *httptest.Server

	client *envoy.Client
)

type payload struct {
	Aud         string `json:"aud"`
	Iss         string `json:"iss"`
	EnphaseUser string `json:"enphaseUser"`
	Exp         int64  `json:"exp"`
	Iat         int64  `json:"iat"`
	Jti         string `json:"jti"`
	Username    string `json:"username"`
}

func setup(t *testing.T) (func(), error) {
	var err error

	muxEnlighten = http.NewServeMux()
	enlightenServer = httptest.NewServer(muxEnlighten)

	muxEnlighten.HandleFunc("/entrez-auth-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		validSession := false
		for _, c := range r.Cookies() {
			if c.Name == "_enlighten_4_session" && c.Value == "baz" {
				validSession = true
			}
		}
		if !validSession {
			w.WriteHeader(http.StatusUnauthorized)
		}
		if serial := r.URL.Query().Get("serial_num"); serial != "12222999" {
			// Return with some JSON here
			w.WriteHeader(http.StatusUnauthorized)
		}
		claims := payload{
			Aud:         "12222999",
			Iss:         "Entrez",
			EnphaseUser: "owner",
			Iat:         time.Now().Unix(),
			Exp:         time.Now().Add(365 * 1440 * time.Minute).Unix(),
			Username:    "foo",
			Jti:         "da0d96cf-fcd1-4415-8b10-46acdd7d9407",
		}
		data, _ := json.Marshal(claims)
		base64Payload := base64.RawStdEncoding.EncodeToString(data)
		tokenResponse := envoy.TokenResponse{
			GenerationTime: time.Now().Unix(),
			Token:          fmt.Sprintf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.%s.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", base64Payload),
			ExpiresAt:      time.Now().Add(time.Minute * 1440 * 365).Unix(),
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse)
	})

	muxEnlighten.HandleFunc("/login/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		username := r.Form.Get("user[email]")
		password := r.Form.Get("user[password]")
		if username == "foo" && password == "bar" {
			http.SetCookie(w, &http.Cookie{
				Name:  "_enlighten_4_session",
				Value: "baz",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"success", "session_id": "baz"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	muxGateway = http.NewServeMux()
	gatewayServer = httptest.NewServer(muxGateway)

	muxGateway.HandleFunc("/auth/check_jwt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) < 2 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := parts[1]
		if len(token) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  "sessionId",
			Value: "baz",
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
	})

	client, err = envoy.NewClient(
		envoy.WithEnlightenBase(enlightenServer.URL),
		envoy.WithGatewayAddress(gatewayServer.URL),
		envoy.WithSerial("12222999"),
		envoy.WithCredentials("foo", "bar"))
	if !assert.Nil(t, err) {
		return func() {
			enlightenServer.Close()
			gatewayServer.Close()
		}, err
	}

	return func() {
		enlightenServer.Close()
		gatewayServer.Close()
	}, nil
}

func TestProduction(t *testing.T) {
	teardown, err := setup(t)
	if !assert.Nil(t, err) {
		return
	}
	defer teardown()

	muxGateway.HandleFunc("/production.json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	resp, err := client.Production()
	if !assert.Nil(t, err) {
		return
	}
	assert.NotNil(t, resp)
}
