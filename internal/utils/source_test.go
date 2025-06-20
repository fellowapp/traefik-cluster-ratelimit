package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExtractor(t *testing.T) {
	testCases := []struct {
		desc     string
		variable string
		secure   bool
		wantErr  bool
	}{
		{
			desc:     "client.ip",
			variable: "client.ip",
			secure:   false,
			wantErr:  false,
		},
		{
			desc:     "request.host",
			variable: "request.host",
			secure:   false,
			wantErr:  false,
		},
		{
			desc:     "request.header.valid",
			variable: "request.header.Authorization",
			secure:   false,
			wantErr:  false,
		},
		{
			desc:     "request.header.empty",
			variable: "request.header.",
			secure:   false,
			wantErr:  true,
		},
		{
			desc:     "unsupported",
			variable: "unsupported",
			secure:   false,
			wantErr:  true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			extractor, err := NewExtractor(test.variable, test.secure)
			
			if test.wantErr {
				assert.Error(t, err)
				assert.Nil(t, extractor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, extractor)
			}
		})
	}
}

func TestHeaderExtractor(t *testing.T) {
	testCases := []struct {
		desc       string
		headerName string
		headerVal  string
		secure     bool
		expected   string
	}{
		{
			desc:       "simple header plain",
			headerName: "X-Test",
			headerVal:  "test-value",
			secure:     false,
			expected:   "test-value",
		},
		{
			desc:       "simple header secure",
			headerName: "X-Test",
			headerVal:  "test-value",
			secure:     true,
			expected:   hashFor("test-value"),
		},
		{
			desc:       "auth header plain",
			headerName: "Authorization",
			headerVal:  "Bearer token123",
			secure:     false,
			expected:   "Bearer token123",
		},
		{
			desc:       "auth header secure",
			headerName: "Authorization",
			headerVal:  "Bearer token123",
			secure:     true,
			expected:   hashFor("Bearer token123"),
		},
		{
			desc:       "empty header",
			headerName: "X-Empty",
			headerVal:  "",
			secure:     true,
			expected:   "",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			extractor, err := NewExtractor("request.header."+test.headerName, test.secure)
			require.NoError(t, err)
			
			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			if test.headerVal != "" {
				req.Header.Set(test.headerName, test.headerVal)
			}
			
			val, _, err := extractor.Extract(req)
			require.NoError(t, err)
			assert.Equal(t, test.expected, val)
		})
	}
}

// Helper to calculate SHA-256 hash for comparison
func hashFor(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
} 