package envoy_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

var hmacSampleSecret []byte

func init() {
	// Load sample key data
	if keyData, e := os.ReadFile("test/hmacTestKey"); e == nil {
		hmacSampleSecret = keyData
	} else {
		panic(e)
	}
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

	client, err = envoy.NewClient("foo", "bar", "12222999",
		envoy.WithEnlightenBase(enlightenServer.URL),
		envoy.WithGatewayAddress(gatewayServer.URL),
		envoy.WithDebug(true),
		envoy.WithNotification(envoy.NilNotification))
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

	productionResponse := `{
  "production": [
    {
      "type": "inverters",
      "activeCount": 17,
      "readingTime": 1672293751,
      "wNow": 0,
      "whLifetime": 61639
    },
    {
      "type": "eim",
      "activeCount": 0,
      "measurementType": "production",
      "readingTime": 1672293852,
      "wNow": -0.699,
      "whLifetime": 0,
      "varhLeadLifetime": 0,
      "varhLagLifetime": 0,
      "vahLifetime": 0,
      "rmsCurrent": 0.202,
      "rmsVoltage": 723.626,
      "reactPwr": 0.714,
      "apprntPwr": 48.254,
      "pwrFactor": 0,
      "whToday": 0,
      "whLastSevenDays": 0,
      "vahToday": 0,
      "varhLeadToday": 0,
      "varhLagToday": 0,
      "lines": [
        {
          "wNow": 0,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0,
          "rmsVoltage": 242.912,
          "reactPwr": 0,
          "apprntPwr": -0,
          "pwrFactor": 0,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        },
        {
          "wNow": -0.699,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0.202,
          "rmsVoltage": 239.602,
          "reactPwr": 0.714,
          "apprntPwr": 48.254,
          "pwrFactor": 0,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        },
        {
          "wNow": -0,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0,
          "rmsVoltage": 241.113,
          "reactPwr": -0,
          "apprntPwr": -0,
          "pwrFactor": -1,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        }
      ]
    }
  ],
  "consumption": [
    {
      "type": "eim",
      "activeCount": 0,
      "measurementType": "total-consumption",
      "readingTime": 1672293852,
      "wNow": -6.063,
      "whLifetime": 0,
      "varhLeadLifetime": 0,
      "varhLagLifetime": 0,
      "vahLifetime": 0,
      "rmsCurrent": -0.206,
      "rmsVoltage": 723.628,
      "reactPwr": -1.751,
      "apprntPwr": -149.166,
      "pwrFactor": -1,
      "whToday": 0,
      "whLastSevenDays": 0,
      "vahToday": 0,
      "varhLeadToday": 0,
      "varhLagToday": 0,
      "lines": [
        {
          "wNow": -3.146,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": -0.207,
          "rmsVoltage": 242.859,
          "reactPwr": -0,
          "apprntPwr": -50.383,
          "pwrFactor": -1,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        },
        {
          "wNow": -0.699,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0.202,
          "rmsVoltage": 239.608,
          "reactPwr": -0.714,
          "apprntPwr": 48.45,
          "pwrFactor": -0.01,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        },
        {
          "wNow": -2.218,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": -0.201,
          "rmsVoltage": 241.162,
          "reactPwr": -1.037,
          "apprntPwr": -48.445,
          "pwrFactor": -1,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        }
      ]
    },
    {
      "type": "eim",
      "activeCount": 0,
      "measurementType": "net-consumption",
      "readingTime": 1672293852,
      "wNow": -5.364,
      "whLifetime": 0,
      "varhLeadLifetime": 0,
      "varhLagLifetime": 0,
      "vahLifetime": 0,
      "rmsCurrent": 0.408,
      "rmsVoltage": 723.63,
      "reactPwr": -1.037,
      "apprntPwr": 98.964,
      "pwrFactor": -0.17,
      "whToday": 0,
      "whLastSevenDays": 0,
      "vahToday": 0,
      "varhLeadToday": 0,
      "varhLagToday": 0,
      "lines": [
        {
          "wNow": -3.146,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0.207,
          "rmsVoltage": 242.805,
          "reactPwr": -0,
          "apprntPwr": 50.37,
          "pwrFactor": -0.33,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        },
        {
          "wNow": -0,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0,
          "rmsVoltage": 239.613,
          "reactPwr": -0,
          "apprntPwr": 0,
          "pwrFactor": 0,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        },
        {
          "wNow": -2.218,
          "whLifetime": 0,
          "varhLeadLifetime": 0,
          "varhLagLifetime": 0,
          "vahLifetime": 0,
          "rmsCurrent": 0.201,
          "rmsVoltage": 241.212,
          "reactPwr": -1.037,
          "apprntPwr": 48.594,
          "pwrFactor": 0,
          "whToday": 0,
          "whLastSevenDays": 0,
          "vahToday": 0,
          "varhLeadToday": 0,
          "varhLagToday": 0
        }
      ]
    }
  ],
  "storage": [
    {
      "type": "acb",
      "activeCount": 0,
      "readingTime": 0,
      "wNow": 0,
      "whNow": 0,
      "state": "idle"
    }
  ]
}`
	muxGateway.HandleFunc("/production.json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(productionResponse))
	})

	res, err := client.Production()
	if !assert.Nil(t, err) {
		return
	}
	if !assert.NotNil(t, res) {
		return
	}
	assert.NotNil(t, res)
}

func TestInverters(t *testing.T) {
	teardown, err := setup(t)
	if !assert.Nil(t, err) {
		return
	}
	defer teardown()

	invertersResponse := `[
  {
    "serialNumber": "482240000001",
    "lastReportDate": 1672392956,
    "devType": 1,
    "lastReportWatts": 14,
    "maxReportWatts": 63
  },
  {
    "serialNumber": "482240000002",
    "lastReportDate": 1672392957,
    "devType": 1,
    "lastReportWatts": 13,
    "maxReportWatts": 60
  }]`
	muxGateway.HandleFunc("/api/v1/production/inverters", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(invertersResponse))
	})

	res, err := client.Inverters()
	if !assert.Nil(t, err) {
		return
	}
	if !assert.NotNil(t, res) {
		return
	}
	assert.Len(t, *res, 2)
}

func TestBatteries(t *testing.T) {
	teardown, err := setup(t)
	if !assert.Nil(t, err) {
		return
	}
	defer teardown()

	invertersResponse := `[
    {
        "type": "ENCHARGE",
        "devices": [
            {
                "part_num": "830-00750-r31",
                "serial_num": "1222345678",
                "installed": 1718870245,
                "device_status": [
                    "envoy.global.ok",
                    "prop.done"
                ],
                "last_rpt_date": 1721246902,
                "admin_state": 6,
                "admin_state_str": "ENCHG_STATE_READY",
                "created_date": 1719970245,
                "img_load_date": 1719970245,
                "img_pnum_running": "2.0.6727_rel/22.15",
                "bmu_fw_version": "2.1.34",
                "communicating": true,
                "sleep_enabled": false,
                "percentFull": 61,
                "temperature": 24,
                "maxCellTemp": 25,
                "reported_enc_grid_state": "grid-tied",
                "comm_level_sub_ghz": 5,
                "comm_level_2_4_ghz": 5,
                "led_status": 12,
                "dc_switch_off": false,
                "encharge_rev": 2,
                "encharge_capacity": 3360,
                "phase": "ph-a",
                "der_index": 2
            },
            {
                "part_num": "830-00750-r31",
                "serial_num": "1234567890",
                "installed": 1720538607,
                "device_status": [
                    "envoy.global.ok",
                    "prop.done"
                ],
                "last_rpt_date": 1721246976,
                "admin_state": 6,
                "admin_state_str": "ENCHG_STATE_READY",
                "created_date": 1720538607,
                "img_load_date": 1720538607,
                "img_pnum_running": "2.0.6727_rel/22.15",
                "bmu_fw_version": "2.1.34",
                "communicating": true,
                "sleep_enabled": false,
                "percentFull": 61,
                "temperature": 24,
                "maxCellTemp": 24,
                "reported_enc_grid_state": "grid-tied",
                "comm_level_sub_ghz": 5,
                "comm_level_2_4_ghz": 5,
                "led_status": 12,
                "dc_switch_off": false,
                "encharge_rev": 2,
                "encharge_capacity": 3360,
                "phase": "ph-a",
                "der_index": 2
            },
            {
                "part_num": "836-00750-r29",
                "serial_num": "49221234567",
                "installed": 1720337267,
                "device_status": [
                    "envoy.global.ok",
                    "prop.done"
                ],
                "last_rpt_date": 1721247048,
                "admin_state": 6,
                "admin_state_str": "ENCHG_STATE_READY",
                "created_date": 1720337267,
                "img_load_date": 1720337267,
                "img_pnum_running": "2.0.6727_rel/22.15",
                "bmu_fw_version": "2.1.34",
                "communicating": true,
                "sleep_enabled": false,
                "percentFull": 61,
                "temperature": 24,
                "maxCellTemp": 24,
                "reported_enc_grid_state": "grid-tied",
                "comm_level_sub_ghz": 5,
                "comm_level_2_4_ghz": 5,
                "led_status": 12,
                "dc_switch_off": false,
                "encharge_rev": 2,
                "encharge_capacity": 3360,
                "phase": "ph-a",
                "der_index": 2
            }
        ]
    },
    {
        "type": "ENPOWER",
        "devices": [
            {
                "part_num": "861-01381-r04",
                "serial_num": "202334071482",
                "installed": 1720570387,
                "device_status": [
                    "envoy.global.ok",
                    "prop.done"
                ],
                "last_rpt_date": 1721247059,
                "admin_state": 24,
                "admin_state_str": "ENPWR_STATE_OPER_CLOSED",
                "created_date": 1720570387,
                "img_load_date": 1720570387,
                "img_pnum_running": "2.0.5729_rel/22.15",
                "communicating": true,
                "temperature": 79,
                "comm_level_sub_ghz": 5,
                "comm_level_2_4_ghz": 5,
                "mains_admin_state": "closed",
                "mains_oper_state": "closed",
                "Enpwr_grid_mode": "multimode-ongrid",
                "Enchg_grid_mode": "multimode-ongrid",
                "Enpwr_relay_state_bm": 15856,
                "Enpwr_curr_state_id": 16
            }
        ]
    }
]`
	muxGateway.HandleFunc("/ivp/ensemble/inventory", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(invertersResponse))
	})

	res, err := client.Batteries()
	if !assert.Nil(t, err) {
		return
	}
	if !assert.NotNil(t, res) {
		return
	}
	assert.Len(t, *res, 3)
}

func TestCommCheck(t *testing.T) {
	teardown, err := setup(t)
	if !assert.Nil(t, err) {
		return
	}
	defer teardown()

	commCheckResponse := `{"482240000001":5,"482240000002":5}`
	muxGateway.HandleFunc("/installer/pcu_comm_check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(commCheckResponse))
	})

	res, err := client.CommCheck()
	if !assert.Nil(t, err) {
		return
	}
	if !assert.NotNil(t, res) {
		return
	}
	assert.Len(t, *res, 2)
}

func TestWithJWT(t *testing.T) {
	c := &envoy.Client{}

	afterTenMinutes := time.Now().Add(10 * time.Minute).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"exp": afterTenMinutes,
	})
	tokenString, err := token.SignedString(hmacSampleSecret)
	if !assert.Nil(t, err) {
		return
	}

	err = envoy.WithJWT(tokenString)(c)

	if !assert.Nil(t, err) {
		return
	}
	expires, err := envoy.GetJWTExpired(tokenString)
	if !assert.Nil(t, err) {
		return
	}
	if !assert.NotNil(t, expires) {
		return
	}
	assert.Equal(t, afterTenMinutes, expires.Unix())
}
