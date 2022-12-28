package envoy

import "fmt"

type OptionFunc func(*Client) error

func WithGatewayAddress(address string) OptionFunc {
	return func(client *Client) error {
		client.gatewayBase = address
		return nil
	}
}

func WithSerial(serial string) OptionFunc {
	return func(client *Client) error {
		client.serial = serial
		return nil
	}
}

func WithEnlightenBase(enlightenBase string) OptionFunc {
	return func(client *Client) error {
		client.enlightenBase = enlightenBase
		return nil
	}
}

func WithCredentials(username, password string) OptionFunc {
	return func(client *Client) error {
		var err error
		client.username = username
		client.password = password

		if client.serial == "" {
			return fmt.Errorf("set serial before credentials")
		}

		client.token, err = getLongLivedJWT(client.enlightenBase, username, password, client.serial)
		if err != nil {
			return fmt.Errorf("getting long lived token with credentials: %w", err)
		}
		return nil
	}
}
