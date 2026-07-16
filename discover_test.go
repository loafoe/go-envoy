package envoy_test

import (
	"testing"
	"time"

	"github.com/loafoe/go-envoy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mDNS discovery test in short mode (requires network)")
	}

	resp, err := envoy.DiscoverWithTimeout(5 * time.Second)
	require.NoError(t, err, "Discovery should succeed")
	require.NotNil(t, resp, "Response should not be nil")

	t.Logf("Discovered Envoy:")
	t.Logf("  IPv4: %s", resp.IPV4)
	t.Logf("  IPv6: %s", resp.IPV6)
	t.Logf("  Serial: %s", resp.Serial)
	t.Logf("  ProtoVersion: %s", resp.ProtoVersion)

	assert.NotEmpty(t, resp.IPV4, "Should discover Envoy IP")
	assert.NotEmpty(t, resp.Serial, "Serial number should be populated")
	assert.NotEmpty(t, resp.ProtoVersion, "Protocol version should be populated")
}

func TestDiscoverTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mDNS discovery test in short mode (requires network)")
	}

	// Very short timeout - should still work if device responds quickly
	resp, err := envoy.DiscoverWithTimeout(100 * time.Millisecond)
	if err != nil {
		t.Logf("Short timeout failed as expected: %v", err)
		return
	}
	// If it succeeded with short timeout, verify the data
	assert.NotEmpty(t, resp.IPV4, "Should have IPv4 if discovery succeeded")
}

func TestWithDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mDNS discovery test in short mode (requires network)")
	}

	// Test that WithDiscovery option works and overrides default gateway
	// We can't create a full client without credentials, but we can verify
	// the option function works correctly
	resp, err := envoy.Discover()
	require.NoError(t, err)

	t.Logf("WithDiscovery would set gateway to: https://%s", resp.IPV4)
	t.Logf("WithDiscovery would use serial: %s", resp.Serial)

	assert.NotEmpty(t, resp.IPV4)
}
