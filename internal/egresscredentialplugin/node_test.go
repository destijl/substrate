// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egresscredentialplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	egresscredentialv1 "github.com/agent-substrate/substrate/pkg/proto/egresscredentialpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewNodePlugin_Validation(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		wantErr    bool
		wantHeader string
	}{
		{
			name:    "missing audience",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "invalid header name with CRLF",
			cfg: Config{
				Audience:   "aud",
				HeaderName: "Bad\r\nHeader",
			},
			wantErr: true,
		},
		{
			name: "invalid header name with spaces",
			cfg: Config{
				Audience:   "aud",
				HeaderName: "Bad Header",
			},
			wantErr: true,
		},
		{
			name: "invalid header name with colon",
			cfg: Config{
				Audience:   "aud",
				HeaderName: "Bad:Header",
			},
			wantErr: true,
		},
		{
			name: "valid custom header",
			cfg: Config{
				Audience:   "aud",
				HeaderName: "X-Custom-Auth",
			},
			wantHeader: "X-Custom-Auth",
		},
		{
			name: "default values applied",
			cfg: Config{
				Audience: "aud",
			},
			wantHeader: DefaultHeaderName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewNodePlugin(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewNodePlugin() err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && p.cfg.HeaderName != tt.wantHeader {
				t.Errorf("HeaderName = %q, want %q", p.cfg.HeaderName, tt.wantHeader)
			}
		})
	}
}

func TestNodePlugin_GetConfig(t *testing.T) {
	p, err := NewNodePlugin(Config{Audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov"})
	if err != nil {
		t.Fatalf("NewNodePlugin() err = %v", err)
	}

	resp, err := p.GetConfig(context.Background(), &egresscredentialv1.GetConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig() err = %v", err)
	}
	if len(resp.GetJwtAudiences()) != 1 || resp.GetJwtAudiences()[0] != p.cfg.Audience {
		t.Errorf("JwtAudiences = %v, want [%q]", resp.GetJwtAudiences(), p.cfg.Audience)
	}
}

func TestNodePlugin_MintConnectHeaders(t *testing.T) {
	tests := []struct {
		name          string
		cfg           Config
		req           *egresscredentialv1.MintConnectHeadersRequest
		serverHandler http.HandlerFunc
		wantCode      codes.Code
		wantHeaderKey string
		wantHeaderVal string
		wantMinExpiry time.Duration
		wantMaxExpiry time.Duration
	}{
		{
			name:     "missing actor_jwt",
			cfg:      Config{Audience: "aud"},
			req:      &egresscredentialv1.MintConnectHeadersRequest{},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "successful token exchange with defaults",
			cfg:  Config{Audience: "aud-test"},
			req:  &egresscredentialv1.MintConnectHeadersRequest{ActorJwt: "jwt-token-123"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("Content-Type = %s, want application/x-www-form-urlencoded", ct)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm() err = %v", err)
				}
				if got := r.FormValue("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
					t.Errorf("grant_type = %q", got)
				}
				if got := r.FormValue("audience"); got != "aud-test" {
					t.Errorf("audience = %q", got)
				}
				if got := r.FormValue("requested_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
					t.Errorf("requested_token_type = %q", got)
				}
				if got := r.FormValue("subject_token_type"); got != "urn:ietf:params:oauth:token-type:jwt" {
					t.Errorf("subject_token_type = %q", got)
				}
				if got := r.FormValue("subject_token"); got != "jwt-token-123" {
					t.Errorf("subject_token = %q", got)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token": "test-access-token-abc", "expires_in": 3600}`))
			},
			wantCode:      codes.OK,
			wantHeaderKey: DefaultHeaderName,
			wantHeaderVal: "test-access-token-abc",
			wantMinExpiry: 3500 * time.Second,
			wantMaxExpiry: 3700 * time.Second,
		},
		{
			name: "custom header name and prefix",
			cfg: Config{
				Audience:     "aud-test",
				HeaderName:   "X-Custom-Token",
				HeaderPrefix: "Bearer ",
			},
			req: &egresscredentialv1.MintConnectHeadersRequest{ActorJwt: "jwt-token-456"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token": "tok123", "expires_in": 1800}`))
			},
			wantCode:      codes.OK,
			wantHeaderKey: "X-Custom-Token",
			wantHeaderVal: "Bearer tok123",
			wantMinExpiry: 1700 * time.Second,
			wantMaxExpiry: 1900 * time.Second,
		},
		{
			name: "zero expires_in defaults to one hour",
			cfg:  Config{Audience: "aud-test"},
			req:  &egresscredentialv1.MintConnectHeadersRequest{ActorJwt: "jwt-token-789"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token": "tok456", "expires_in": 0}`))
			},
			wantCode:      codes.OK,
			wantHeaderKey: DefaultHeaderName,
			wantHeaderVal: "tok456",
			wantMinExpiry: 3500 * time.Second,
			wantMaxExpiry: 3700 * time.Second,
		},
		{
			name: "non-200 STS error status",
			cfg:  Config{Audience: "aud-test"},
			req:  &egresscredentialv1.MintConnectHeadersRequest{ActorJwt: "sensitive-jwt"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error": "forbidden"}`))
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "empty access_token in STS response",
			cfg:  Config{Audience: "aud-test"},
			req:  &egresscredentialv1.MintConnectHeadersRequest{ActorJwt: "valid-jwt"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token": "", "expires_in": 3600}`))
			},
			wantCode: codes.Internal,
		},
		{
			name: "invalid JSON response from STS",
			cfg:  Config{Audience: "aud-test"},
			req:  &egresscredentialv1.MintConnectHeadersRequest{ActorJwt: "valid-jwt"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`not json`))
			},
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.serverHandler != nil {
				ts := httptest.NewServer(tt.serverHandler)
				defer ts.Close()
				tt.cfg.STSEndpoint = ts.URL
				tt.cfg.HTTPClient = ts.Client()
			}

			p, err := NewNodePlugin(tt.cfg)
			if err != nil {
				t.Fatalf("NewNodePlugin() err = %v", err)
			}

			start := time.Now()
			resp, err := p.MintConnectHeaders(context.Background(), tt.req)

			if st, ok := status.FromError(err); ok {
				if st.Code() != tt.wantCode {
					t.Fatalf("MintConnectHeaders() code = %v, want %v (err: %v)", st.Code(), tt.wantCode, err)
				}
				if tt.wantCode != codes.OK {
					// Verify raw token is never leaked into error messages.
					if strings.Contains(err.Error(), "sensitive-jwt") {
						t.Errorf("error leaked token material: %v", err)
					}
					return
				}
			} else if tt.wantCode != codes.OK {
				t.Fatalf("MintConnectHeaders() err = %v, want code %v", err, tt.wantCode)
			}

			val, ok := resp.GetConnectHeaders()[tt.wantHeaderKey]
			if !ok {
				t.Fatalf("missing expected header %q in %v", tt.wantHeaderKey, resp.GetConnectHeaders())
			}
			if val != tt.wantHeaderVal {
				t.Errorf("header value = %q, want %q", val, tt.wantHeaderVal)
			}

			expiresDuration := time.Unix(resp.GetExpiresAtUnixSec(), 0).Sub(start)
			if expiresDuration < tt.wantMinExpiry || expiresDuration > tt.wantMaxExpiry {
				t.Errorf("expires duration = %v, want between %v and %v", expiresDuration, tt.wantMinExpiry, tt.wantMaxExpiry)
			}
		})
	}
}
