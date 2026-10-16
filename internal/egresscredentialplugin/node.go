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

// Package egresscredentialplugin implements the node egress-credential provider.
package egresscredentialplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	egresscredentialv1 "github.com/agent-substrate/substrate/pkg/proto/egresscredentialpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// DefaultSTSEndpoint is the default Google STS token exchange endpoint.
	DefaultSTSEndpoint = "https://sts.googleapis.com/v1/token"

	// DefaultScope is the default OAuth 2.0 scope for GCP token exchange.
	DefaultScope = "https://www.googleapis.com/auth/cloud-platform"

	// DefaultHeaderName is the default HTTP CONNECT header name.
	DefaultHeaderName = "Workload-Access-Token"
)

// Config configures the node egress credential plugin.
type Config struct {
	STSEndpoint  string
	Audience     string
	Scope        string
	HeaderName   string
	HeaderPrefix string
	HTTPClient   *http.Client
}

// NodePlugin implements egresscredentialv1.NodeProviderServer.
type NodePlugin struct {
	egresscredentialv1.UnimplementedNodeProviderServer
	cfg Config
}

// NewNodePlugin returns a new NodePlugin with validated configuration.
func NewNodePlugin(cfg Config) (*NodePlugin, error) {
	if cfg.Audience == "" {
		return nil, errors.New("audience is required")
	}
	if cfg.STSEndpoint == "" {
		cfg.STSEndpoint = DefaultSTSEndpoint
	}
	if cfg.Scope == "" {
		cfg.Scope = DefaultScope
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = DefaultHeaderName
	}
	if http.CanonicalHeaderKey(cfg.HeaderName) == "" || !isValidHeaderName(cfg.HeaderName) {
		return nil, fmt.Errorf("invalid header name %q", cfg.HeaderName)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &NodePlugin{cfg: cfg}, nil
}

// GetConfig returns the configured JWT audiences needed to mint actor tokens.
func (p *NodePlugin) GetConfig(ctx context.Context, req *egresscredentialv1.GetConfigRequest) (*egresscredentialv1.GetConfigResponse, error) {
	return &egresscredentialv1.GetConfigResponse{
		JwtAudiences: []string{p.cfg.Audience},
	}, nil
}

type stsResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// MintConnectHeaders exchanges the actor JWT at STS and returns CONNECT headers.
func (p *NodePlugin) MintConnectHeaders(ctx context.Context, req *egresscredentialv1.MintConnectHeadersRequest) (*egresscredentialv1.MintConnectHeadersResponse, error) {
	if req.GetActorJwt() == "" {
		return nil, status.Error(codes.InvalidArgument, "actor_jwt is required")
	}

	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {p.cfg.Audience},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":        {req.GetActorJwt()},
	}
	if p.cfg.Scope != "" {
		form.Set("scope", p.cfg.Scope)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.STSEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create STS request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "STS token exchange request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read STS response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.PermissionDenied, "STS token exchange failed with status %d", resp.StatusCode)
	}

	var tokResp stsResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, status.Errorf(codes.Internal, "parse STS response: %v", err)
	}
	if tokResp.AccessToken == "" {
		return nil, status.Error(codes.Internal, "STS response missing access_token")
	}

	var expiresAt int64
	if tokResp.ExpiresIn <= 0 {
		expiresAt = time.Now().Add(time.Hour).Unix()
	} else {
		expiresAt = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second).Unix()
	}

	return &egresscredentialv1.MintConnectHeadersResponse{
		ConnectHeaders: map[string]string{
			p.cfg.HeaderName: p.cfg.HeaderPrefix + tokResp.AccessToken,
		},
		ExpiresAtUnixSec: expiresAt,
	}, nil
}

func isValidHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z':
		case 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
			c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
			c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}
