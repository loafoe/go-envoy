package envoy

import (
	"context"
	"errors"
	"time"

	"github.com/brutella/dnssd"
)

func Discover() (string, error) {
	discovered := ""
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	found := func(e dnssd.BrowseEntry) {
		// look through the list of IPs, pick something IPv4
		for _, ipa := range e.IPs {
			if ipa.To4() != nil {
				discovered = ipa.String()
				cancel()
				return
			}
		}
	}

	if err := dnssd.LookupType(ctx, "_enphase-envoy._tcp.local.", found, func(_ dnssd.BrowseEntry) {

	}); err != nil {
		if !errors.Is(err, context.Canceled) {
			return "", err
		}
	}
	return discovered, nil
}
