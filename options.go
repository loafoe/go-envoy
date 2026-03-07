package envoy

import (
	"fmt"
	"time"
)

type OptionFunc func(*Client) error

func WithJWT(rawToken string) OptionFunc {
	return func(client *Client) error {
		// Treat empty token as noop
		if rawToken == "" {
			return nil
		}
		client.jwtAtInit = true

		token, err := parseUnverified(rawToken)
		if err != nil {
			return err
		}
		client.token = token
		jwtExpires, err := GetJWTExpired(rawToken)
		if err != nil {
			return err
		}
		if jwtExpires.Before(time.Now()) {
			return fmt.Errorf("JWT has expired: %v", jwtExpires)
		}
		client.jwtExpires = *jwtExpires
		return nil
	}
}

func WithGatewayAddress(address string) OptionFunc {
	return func(client *Client) error {
		client.gatewayBase = address
		return nil
	}
}

func WithEnlightenBase(enlightenBase string) OptionFunc {
	return func(client *Client) error {
		client.enlightenBase = enlightenBase
		return nil
	}
}

func WithDebug(debug bool) OptionFunc {
	return func(client *Client) error {
		client.debug = debug
		return nil
	}
}

func WithNotification(notification Notification) OptionFunc {
	return func(client *Client) error {
		client.notification = notification
		return nil
	}
}

func WithDiscovery() OptionFunc {
	return func(client *Client) error {
		resp, err := Discover()
		if err != nil {
			return fmt.Errorf("mDNS discovery failed: %w", err)
		}
		if resp.IPV4 != "" {
			client.gatewayBase = fmt.Sprintf("https://%s", resp.IPV4)
		} else if resp.IPV6 != "" {
			client.gatewayBase = fmt.Sprintf("https://[%s]", resp.IPV6)
		} else {
			return fmt.Errorf("mDNS discovery returned no IP address")
		}
		if client.serial == "" && resp.Serial != "" {
			client.serial = resp.Serial
		}
		return nil
	}
}
