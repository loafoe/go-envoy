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
					ipStr := entry.AddrV4.String()
					if ipStr != "<nil>" {
						response.IPV4 = ipStr
					}
				}
				if entry.AddrV6 != nil {
					ipStr := entry.AddrV6.String()
					if ipStr != "<nil>" {
						response.IPV6 = ipStr
					}
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

	if response.IPV4 == "" && response.IPV6 == "" {
		return nil, fmt.Errorf("envoy device found but no valid IP address resolved within %v", timeout)
	}

	return &response, nil
}
