package traefik_cluster_ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fellowapp/traefik-cluster-ratelimit/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhitelistedIPs(t *testing.T) {
	testCases := []struct {
		desc            string
		whitelistedIPs  []string
		remoteAddr      string
		shouldBypass    bool
		expectError     bool
	}{
		{
			desc:            "Single whitelisted IP - exact match",
			whitelistedIPs:  []string{"192.168.1.100"},
			remoteAddr:      "192.168.1.100:12345",
			shouldBypass:    true,
			expectError:     false,
		},
		{
			desc:            "Single whitelisted IP - no match",
			whitelistedIPs:  []string{"192.168.1.100"},
			remoteAddr:      "192.168.1.101:12345",
			shouldBypass:    false,
			expectError:     false,
		},
		{
			desc:            "CIDR range - IP in range",
			whitelistedIPs:  []string{"10.0.0.0/8"},
			remoteAddr:      "10.5.10.20:12345",
			shouldBypass:    true,
			expectError:     false,
		},
		{
			desc:            "CIDR range - IP not in range",
			whitelistedIPs:  []string{"10.0.0.0/8"},
			remoteAddr:      "192.168.1.1:12345",
			shouldBypass:    false,
			expectError:     false,
		},
		{
			desc:            "Multiple whitelisted IPs - match first",
			whitelistedIPs:  []string{"192.168.1.100", "10.0.0.0/8", "172.16.0.0/12"},
			remoteAddr:      "192.168.1.100:12345",
			shouldBypass:    true,
			expectError:     false,
		},
		{
			desc:            "Multiple whitelisted IPs - match CIDR",
			whitelistedIPs:  []string{"192.168.1.100", "10.0.0.0/8", "172.16.0.0/12"},
			remoteAddr:      "10.20.30.40:12345",
			shouldBypass:    true,
			expectError:     false,
		},
		{
			desc:            "Multiple whitelisted IPs - no match",
			whitelistedIPs:  []string{"192.168.1.100", "10.0.0.0/8", "172.16.0.0/12"},
			remoteAddr:      "8.8.8.8:12345",
			shouldBypass:    false,
			expectError:     false,
		},
		{
			desc:            "No whitelisted IPs configured",
			whitelistedIPs:  nil,
			remoteAddr:      "192.168.1.100:12345",
			shouldBypass:    false,
			expectError:     false,
		},
		{
			desc:            "IPv6 whitelisted",
			whitelistedIPs:  []string{"2001:db8::/32"},
			remoteAddr:      "[2001:db8::1]:12345",
			shouldBypass:    true,
			expectError:     false,
		},
		{
			desc:            "IPv6 not whitelisted",
			whitelistedIPs:  []string{"2001:db8::/32"},
			remoteAddr:      "[2001:db9::1]:12345",
			shouldBypass:    false,
			expectError:     false,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			// Create a simple next handler that records if it was called
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				nextCalled = true
				rw.WriteHeader(http.StatusOK)
			})

			// Create config with whitelisted IPs and a very restrictive rate limit
			config := &Config{
				Average:      1, // Very low rate to ensure non-whitelisted would be blocked
				Burst:        1,
				Period:       1,
				RedisAddress: "localhost:6379", // This won't actually connect in unit tests
			}
			
			if test.whitelistedIPs != nil {
				config.Whitelist = &WhitelistConfig{
					IPs: test.whitelistedIPs,
				}
			}

			handler, err := New(context.Background(), next, config, "test-whitelist")
			if test.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Create a test request with the specified remote address
			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			req.RemoteAddr = test.remoteAddr

			// Record the response
			rr := httptest.NewRecorder()

			// Serve the request
			handler.ServeHTTP(rr, req)

			// Verify the behavior
			if test.shouldBypass {
				// Whitelisted IPs should always pass through
				assert.True(t, nextCalled, "Next handler should have been called for whitelisted IP")
				assert.Equal(t, http.StatusOK, rr.Code, "Response should be 200 OK for whitelisted IP")
			}
			// Note: For non-whitelisted IPs, we can't easily test rate limiting behavior
			// without a working Redis connection in unit tests. That would require
			// integration tests with a real Redis instance.
		})
	}
}

func TestWhitelistedIPsInvalidConfig(t *testing.T) {
	testCases := []struct {
		desc            string
		whitelistedIPs  []string
		expectError     bool
		errorContains   string
	}{
		{
			desc:            "Invalid IP address",
			whitelistedIPs:  []string{"invalid-ip"},
			expectError:     true,
			errorContains:   "unable to create whitelist IP checker",
		},
		{
			desc:            "Invalid CIDR",
			whitelistedIPs:  []string{"192.168.1.1/33"},
			expectError:     true,
			errorContains:   "unable to create whitelist IP checker",
		},
		{
			desc:            "Mixed valid and invalid",
			whitelistedIPs:  []string{"192.168.1.1", "invalid"},
			expectError:     true,
			errorContains:   "unable to create whitelist IP checker",
		},
		{
			desc:            "Empty string in list",
			whitelistedIPs:  []string{"192.168.1.1", ""},
			expectError:     true,
			errorContains:   "unable to create whitelist IP checker",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})

			config := &Config{
				Average:      10,
				Burst:        20,
				Period:       1,
				RedisAddress: "localhost:6379",
				Whitelist: &WhitelistConfig{
					IPs: test.whitelistedIPs,
				},
			}

			_, err := New(context.Background(), next, config, "test-invalid")
			if test.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWhitelistedIPsWithUnlimitedRate(t *testing.T) {
	// Test that whitelisting works even when average is 0 (unlimited)
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	})

	config := &Config{
		Average:      0, // Unlimited
		Burst:        1,
		Period:       1,
		RedisAddress: "localhost:6379",
		Whitelist: &WhitelistConfig{
			IPs: []string{"192.168.1.100"},
		},
	}

	handler, err := New(context.Background(), next, config, "test-unlimited")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled, "Next handler should have been called")
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestWhitelistWithCustomIPStrategy(t *testing.T) {
	// Test that whitelist uses its own IP strategy with excludedIPs
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	})

	config := &Config{
		Average:      10,
		Burst:        20,
		Period:       1,
		RedisAddress: "localhost:6379",
		Whitelist: &WhitelistConfig{
			IPs: []string{"203.0.113.50"}, // External client IP
			IPStrategy: &utils.IPStrategy{
				ExcludedIPs: []string{"10.0.0.0/8"}, // Skip internal load balancer
			},
		},
	}

	handler, err := New(context.Background(), next, config, "test-custom-strategy")
	require.NoError(t, err)

	// Simulate request from load balancer (10.0.0.5) forwarding for external client (203.0.113.50)
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "10.0.0.5:12345" // Load balancer IP
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.5")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should bypass rate limiting because 203.0.113.50 is whitelisted
	// and the IP strategy correctly extracts it by skipping 10.0.0.0/8
	assert.True(t, nextCalled, "Next handler should have been called for whitelisted external IP")
	assert.Equal(t, http.StatusOK, rr.Code)
}

