package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSourceExtractor(t *testing.T) {
	testCases := []struct {
		desc            string
		criterion       *SourceCriterion
		wantErr         bool
		requestSetup    func(*http.Request)
		expectedValue   string
		additionalCheck func(*testing.T, SourceExtractor)
	}{
		{
			desc:      "nil source criterion",
			criterion: nil,
			wantErr:   false,
			requestSetup: func(req *http.Request) {
				req.RemoteAddr = "192.168.1.1:1234"
			},
			expectedValue: "192.168.1.1",
		},
		{
			desc:      "empty source criterion",
			criterion: &SourceCriterion{},
			wantErr:   false,
			requestSetup: func(req *http.Request) {
				req.RemoteAddr = "192.168.1.2:1234"
			},
			expectedValue: "192.168.1.2",
		},
		{
			desc: "ip strategy",
			criterion: &SourceCriterion{
				IPStrategy: &IPStrategy{},
			},
			wantErr: false,
			requestSetup: func(req *http.Request) {
				req.RemoteAddr = "192.168.1.3:1234"
			},
			expectedValue: "192.168.1.3",
		},
		{
			desc: "request host",
			criterion: &SourceCriterion{
				RequestHost: true,
			},
			wantErr: false,
			requestSetup: func(req *http.Request) {
				req.Host = "example.com"
			},
			expectedValue: "example.com",
		},
		{
			desc: "request header with secure default (true)",
			criterion: &SourceCriterion{
				RequestHeaderName: "Authorization",
			},
			wantErr: false,
			requestSetup: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer testtoken")
			},
			expectedValue: hashFor("Bearer testtoken"),
		},
		{
			desc: "request header with secure explicitly true",
			criterion: &SourceCriterion{
				RequestHeaderName: "Authorization",
				Secure:           boolPtr(true),
			},
			wantErr: false,
			requestSetup: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer testtoken2")
			},
			expectedValue: hashFor("Bearer testtoken2"),
		},
		{
			desc: "request header with secure false",
			criterion: &SourceCriterion{
				RequestHeaderName: "Authorization",
				Secure:           boolPtr(false),
			},
			wantErr: false,
			requestSetup: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer testtoken3")
			},
			expectedValue: "Bearer testtoken3",
		},
		{
			desc: "multiple exclusive sources - ip and header",
			criterion: &SourceCriterion{
				IPStrategy:        &IPStrategy{},
				RequestHeaderName: "X-Test",
			},
			wantErr: true,
		},
		{
			desc: "multiple exclusive sources - ip and host",
			criterion: &SourceCriterion{
				IPStrategy:  &IPStrategy{},
				RequestHost: true,
			},
			wantErr: true,
		},
		{
			desc: "multiple exclusive sources - header and host",
			criterion: &SourceCriterion{
				RequestHeaderName: "X-Test",
				RequestHost:       true,
			},
			wantErr: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			extractor, err := GetSourceExtractor(test.criterion)

			if test.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, extractor)

			if test.requestSetup != nil && test.expectedValue != "" {
				req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
				test.requestSetup(req)

				val, _, err := extractor.Extract(req)
				require.NoError(t, err)
				assert.Equal(t, test.expectedValue, val)
			}

			if test.additionalCheck != nil {
				test.additionalCheck(t, extractor)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
} 