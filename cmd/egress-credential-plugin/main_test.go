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

package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/pluginsocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestHealthcheck(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "plugin.sock")

	lis, err := pluginsocket.Listen(socket)
	if err != nil {
		t.Fatalf("Listen() err = %v", err)
	}
	defer lis.Close()

	srv := grpc.NewServer()
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(srv, healthSrv)
	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	// Wait for listener to be ready.
	for i := 0; i < 50; i++ {
		conn, dialErr := net.Dial("unix", socket)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx := context.Background()
	if err := healthcheck(ctx, socket, 2*time.Second); err != nil {
		t.Fatalf("healthcheck() err = %v, want nil", err)
	}
}
