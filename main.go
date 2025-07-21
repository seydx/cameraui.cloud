package main

import (
	"github.com/seydx/cameraui.com/cloud-client/internal/app"
	"github.com/seydx/cameraui.com/cloud-client/internal/proxy"
	"github.com/seydx/cameraui.com/cloud-client/internal/tunnel"
	"github.com/seydx/cameraui.com/cloud-client/pkg/log"
	"github.com/seydx/cameraui.com/cloud-client/pkg/shell"
)

func main() {
	app.Version = "0.0.1"

	// Initialize logger
	log.Init()

	// Initialize app
	app.Init()

	// Initialize proxy
	proxy.Init()

	// Initialize tunnel
	tunnel.Init()

	// Wait until a signal is received
	shell.RunUntilSignal()
}
