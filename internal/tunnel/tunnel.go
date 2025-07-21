package tunnel

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nats-io/nats.go"
	"github.com/seydx/cameraui.com/cloud-client/internal/app"
	"github.com/seydx/cameraui.com/cloud-client/internal/proxy"
	"github.com/seydx/cameraui.com/cloud-client/pkg/log"
)

type TunnelConnection struct {
	// Config
	ServerID     string
	ServerSecret string
	SessionID    string
	Challenge    string
	Endpoint     string
	LocalPort    string

	// State
	conn        net.Conn
	session     *yamux.Session
	connected   atomic.Bool
	ConnectedAt time.Time
	mu          sync.Mutex

	// Callbacks
	OnConnected    func()
	OnDisconnected func(reason string)
	OnError        func(error)
}

type AuthFrame struct {
	Type      string `json:"type"`
	ServerID  string `json:"server_id"`
	SessionID string `json:"session_id"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type TunnelRequest struct {
	ServerID      string `json:"serverId"`
	ServerSecret  string `json:"serverSecret"`
	SessionID     string `json:"sessionId"`
	Challenge     string `json:"challenge"`
	ProxyEndpoint string `json:"proxyEndpoint"`
	Timestamp     int64  `json:"timestamp"`
}

var currentTunnel *TunnelConnection

var (
	ConnectSubject    = "cloud.tunnel.connect"
	DisconnectSubject = "cloud.tunnel.disconnect"
	StatusSubject     = "cloud.tunnel.status"
)

func Init() {
	proxyClient := proxy.GetClient()
	if proxyClient == nil {
		log.Logger.Fatal().Msg("Proxy client is not initialized")
	}

	// Handle tunnel requests (request/response pattern)
	proxyClient.RegisterHandler(ConnectSubject, func(msg *nats.Msg) {
		var req TunnelRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			proxyClient.RespondError(msg, err.Error())
			return
		}

		// Handle connection
		if err := handleConnect(req); err != nil {
			proxyClient.RespondError(msg, err.Error())
		} else {
			proxyClient.RespondSuccess(msg, map[string]interface{}{
				"status":   "connected",
				"serverId": req.ServerID,
			})
		}
	})

	// Handle disconnect requests
	proxyClient.RegisterHandler(DisconnectSubject, func(msg *nats.Msg) {
		if currentTunnel != nil {
			currentTunnel.Close()
			currentTunnel = nil
		}

		proxyClient.RespondSuccess(msg, map[string]interface{}{
			"status": "disconnected",
		})
	})

	// Handle status requests
	proxyClient.RegisterHandler(StatusSubject, func(msg *nats.Msg) {
		if currentTunnel == nil {
			proxyClient.RespondSuccess(msg, map[string]interface{}{
				"connected": false,
			})
			return
		}

		proxyClient.RespondSuccess(msg, map[string]interface{}{
			"connected": true,
		})
	})
}

func handleConnect(req TunnelRequest) error {
	if currentTunnel != nil {
		currentTunnel.Close()
	}

	// Create new tunnel connection
	currentTunnel = NewTunnelConnection(
		req.ServerID,
		req.ServerSecret,
		req.SessionID,
		req.Challenge,
		req.ProxyEndpoint,
	)

	// Set up event handlers
	currentTunnel.OnConnected = func() {
		log.Logger.Info().Str("serverId", req.ServerID).Msg("Tunnel connected")
	}

	currentTunnel.OnDisconnected = func(reason string) {
		log.Logger.Warn().Str("serverId", req.ServerID).Str("reason", reason).Msg("Tunnel disconnected")
	}

	currentTunnel.OnError = func(err error) {
		log.Logger.Error().Err(err).Msg("Tunnel error")
	}

	return currentTunnel.Connect()
}

func NewTunnelConnection(serverID, serverSecret, sessionID, challenge, endpoint string) *TunnelConnection {
	cfg := app.GetConfig()

	return &TunnelConnection{
		ServerID:     serverID,
		ServerSecret: serverSecret,
		SessionID:    sessionID,
		Challenge:    challenge,
		Endpoint:     endpoint,
		LocalPort:    cfg.LocalPort,
	}
}

func (t *TunnelConnection) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Parse endpoint
	host, port, err := net.SplitHostPort(t.Endpoint)
	if err != nil {
		// No port specified, use default
		host = t.Endpoint
		port = "8093"
	}

	// Connect with TLS
	conn, err := tls.Dial("tcp", t.Endpoint, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%s: %w", host, port, err)
	}

	t.conn = conn

	// Send auth frame
	authFrame := &AuthFrame{
		Type:      "AUTH",
		ServerID:  t.ServerID,
		SessionID: t.SessionID,
		Timestamp: time.Now().Unix(),
	}

	// Calculate signature
	payload := fmt.Sprintf("%s:%s:%d", t.Challenge, t.SessionID, authFrame.Timestamp)
	authFrame.Signature = t.calculateHMAC(payload)

	// Send as JSON + newline
	authJSON, err := json.Marshal(authFrame)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to marshal auth frame: %w", err)
	}

	if _, err := conn.Write(append(authJSON, '\n')); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send auth frame: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	response = strings.TrimSpace(response)
	if response != "OK" {
		conn.Close()
		return fmt.Errorf("authentication failed: %s", response)
	}

	// Create YAMUX session
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.AcceptBacklog = 256
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = 30 * time.Second
	yamuxConfig.MaxStreamWindowSize = 256 * 1024 // 256KB
	yamuxConfig.LogOutput = io.Discard

	session, err := yamux.Client(conn, yamuxConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create yamux session: %w", err)
	}

	t.session = session
	t.connected.Store(true)
	t.ConnectedAt = time.Now()

	// Start accepting streams
	go t.acceptStreams()

	// Notify connected
	if t.OnConnected != nil {
		t.OnConnected()
	}

	return nil
}

func (t *TunnelConnection) acceptStreams() {
	for {
		stream, err := t.session.Accept()
		if err != nil {
			if t.connected.Load() {
				if t.OnError != nil {
					t.OnError(fmt.Errorf("failed to accept stream: %w", err))
				}
			}
			break
		}

		// Handle stream
		go t.handleStream(stream)
	}

	// Session ended
	t.disconnect("session closed")
}

func (t *TunnelConnection) handleStream(stream net.Conn) {
	defer stream.Close()

	// Connect to local service
	local, err := net.Dial("tcp", net.JoinHostPort("localhost", t.LocalPort))
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to connect to local port %s: %w", t.LocalPort, err))
		}
		return
	}
	defer local.Close()

	// Bidirectional copy with stats
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> Local
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, stream)
	}()

	// Local -> Stream
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, local)
	}()

	wg.Wait()
}

func (t *TunnelConnection) calculateHMAC(payload string) string {
	h := hmac.New(sha256.New, []byte(t.ServerSecret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func (t *TunnelConnection) disconnect(reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected.Load() {
		return
	}

	t.connected.Store(false)

	if t.session != nil {
		t.session.Close()
		t.session = nil
	}

	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}

	if t.OnDisconnected != nil {
		t.OnDisconnected(reason)
	}
}

func (t *TunnelConnection) Close() {
	t.disconnect("closed by user")
}

func (t *TunnelConnection) IsConnected() bool {
	return t.connected.Load()
}
