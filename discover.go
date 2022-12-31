package envoy

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

const serviceLookup = "_enphase-envoy._tcp"

func Discover() (*DiscoverResponse, error) {
	var response DiscoverResponse

	done := make(chan bool)
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	go func() {
		for entry := range entriesCh {
			if entry.Name == "envoy._enphase-envoy._tcp.local." {
				response.IPV4 = entry.AddrV4.String()
				response.IPV6 = entry.AddrV6.String()
				for _, f := range entry.InfoFields {
					parts := strings.Split(f, "=")
					if len(parts) > 0 {
						switch parts[0] {
						case "protovers":
							response.ProtoVersion = parts[1]
						case "serialnum":
							response.Serial = parts[1]
						}

					}
				}
				done <- true
				break
			}
		}
	}()

	// Start the lookup
	_ = mdns.Lookup(serviceLookup, entriesCh)

	select {
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timed out trying to discover service '%s'", serviceLookup)
	case <-done:
	}
	close(entriesCh)

	return &response, nil
}
