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

// Command egress-credential-plugin serves the egress credential plugin API
// over a Unix socket. It runs as a sidecar next to atelet in "node" mode.
// "healthcheck" reports whether a running plugin is serving, for the sidecar's
// startup probe.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agent-substrate/substrate/internal/egresscredentialplugin"
	"github.com/agent-substrate/substrate/internal/pluginsocket"
	"github.com/agent-substrate/substrate/internal/preview"
	"github.com/agent-substrate/substrate/internal/serverboot"
	egresscredentialv1 "github.com/agent-substrate/substrate/pkg/proto/egresscredentialpb/v1"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const usage = `usage: egress-credential-plugin <node|healthcheck> [flags]`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	mode := os.Args[1]
	flags := pflag.NewFlagSet(mode, pflag.ExitOnError)
	socket := flags.String("socket", "", "Unix socket to serve on, or to check in healthcheck mode")
	stsEndpoint := flags.String("sts-endpoint", egresscredentialplugin.DefaultSTSEndpoint, "STS token exchange endpoint URL")
	audience := flags.String("audience", "", "node mode: target audience for the actor JWT and STS token exchange")
	scope := flags.String("scope", egresscredentialplugin.DefaultScope, "node mode: OAuth 2.0 scope for the minted token")
	headerName := flags.String("header-name", egresscredentialplugin.DefaultHeaderName, "node mode: HTTP header name attached to egress CONNECT requests")
	headerPrefix := flags.String("header-prefix", "", "node mode: prefix prepended to the access token in the header value")
	timeout := flags.Duration("timeout", 5*time.Second, "healthcheck mode: how long to wait for the plugin to report that it is serving")
	previewFlags := flags.StringSlice("preview", nil, "Preview gates to enable.")
	_ = flags.Parse(os.Args[2:])

	ctx := context.Background()
	serverboot.InitLogger()
	if err := preview.Init(*previewFlags...); err != nil {
		serverboot.Fatal(ctx, "Invalid --preview", err)
	}
	if *socket == "" {
		serverboot.Fatal(ctx, "Missing --socket", fmt.Errorf("--socket is required"))
	}

	if mode == "healthcheck" {
		if err := healthcheck(ctx, *socket, *timeout); err != nil {
			serverboot.Fatal(ctx, "Egress-credential plugin is not serving", err)
		}
		return
	}

	tp, err := serverboot.InitTracing(ctx, serverboot.TracingOptions{
		ServiceName: "egress-credential-plugin-" + mode,
		Sampling:    serverboot.ResolveTraceSampling(ctx, serverboot.ParentRatioSampling(serverboot.ControlPlaneTraceRatio)),
	})
	if err != nil {
		serverboot.Fatal(ctx, "Failed to initialize tracing", err)
	}
	defer serverboot.ShutdownProvider("TracerProvider", tp.Shutdown)

	srv := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
	switch mode {
	case "node":
		plugin, err := egresscredentialplugin.NewNodePlugin(egresscredentialplugin.Config{
			STSEndpoint:  *stsEndpoint,
			Audience:     *audience,
			Scope:        *scope,
			HeaderName:   *headerName,
			HeaderPrefix: *headerPrefix,
		})
		if err != nil {
			serverboot.Fatal(ctx, "Invalid node plugin configuration", err)
		}
		egresscredentialv1.RegisterNodeProviderServer(srv, plugin)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	healthpb.RegisterHealthServer(srv, health.NewServer())

	lis, err := pluginsocket.Listen(*socket)
	if err != nil {
		serverboot.Fatal(ctx, "Failed to listen", err)
	}

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-sigCtx.Done()
		slog.InfoContext(ctx, "Draining egress-credential plugin")
		srv.GracefulStop()
	}()

	slog.InfoContext(ctx, "Serving egress-credential plugin", slog.String("mode", mode), slog.String("socket", *socket))
	if err := srv.Serve(lis); err != nil {
		serverboot.Fatal(ctx, "Serve failed", err)
	}
}

// healthcheck dials the plugin at socket and waits up to timeout for it to
// report that it is serving.
func healthcheck(ctx context.Context, socket string, timeout time.Duration) error {
	conn, err := pluginsocket.Dial(socket, pluginsocket.ReadyWait)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return pluginsocket.WaitReady(ctx, conn)
}
