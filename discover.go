package envoy

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

const serviceLookup = "_enphase-envoy._tcp"

func Discover() (*DiscoverResponse, error) {
	return DiscoverWithTimeout(5 * time.Second)
}

func DiscoverWithTimeout(timeout time.Duration) (*DiscoverResponse, error) {
	var response DiscoverResponse
	found := false

	entriesCh := make(chan *mdns.ServiceEntry, 4)

	go func() {
		for entry := range entriesCh {
			if strings.HasSuffix(entry.Name, "_enphase-envoy._tcp.local.") {
				if entry.AddrV4 != nil {
					response.IPV4 = entry.AddrV4.String()
				}
				if entry.AddrV6 != nil {
					response.IPV6 = entry.AddrV6.String()
				}
				for _, f := range entry.InfoFields {
					parts := strings.Split(f, "=")
					if len(parts) == 2 {
						switch parts[0] {
						case "protovers":
							response.ProtoVersion = parts[1]
						case "serialnum":
							response.Serial = parts[1]
						}
					}
				}
				found = true
			}
		}
	}()

	params := mdns.DefaultParams(serviceLookup)
	params.Entries = entriesCh
	params.Timeout = timeout

	err := mdns.Query(params)
	close(entriesCh)

	if err != nil {
		return nil, fmt.Errorf("mdns query failed: %w", err)
	}

	if !found {
		return nil, fmt.Errorf("no envoy device found via mDNS within %v", timeout)
	}

	return &response, nil
}
