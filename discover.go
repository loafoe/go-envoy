package envoy

import (
	"context"
	"errors"

	"github.com/brutella/dnssd"
)

func Discover(ctx context.Context) (string, error) {
	discovered := ""

	found := func(e dnssd.BrowseEntry) {
		for _, ipa := range e.IPs {
			if ipa.To4() != nil {
				discovered = ipa.String()
				return
			}
		}
	}
	err := dnssd.LookupType(ctx, "_enphase-envoy._tcp.local.", found, func(entry dnssd.BrowseEntry) {
	})
	if !errors.Is(err, context.Canceled) {
		return "", err
	}

	return discovered, nil
}
