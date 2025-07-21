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
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nats-io/nats.go"
	"github.com/seydx/cameraui.com/cloud-client/internal/app"
	"github.com/seydx/cameraui.com/cloud-client/internal/packer"
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

// AuthFrame is the first message sent when establishing a tunnel connection.
// It contains authentication data that the proxy will verify with the cloud service.
type AuthFrame struct {
	Type      string `json:"type"`       // Should be "AUTH"
	ServerID  string `json:"server_id"`  // Server ID
	SessionID string `json:"session_id"` // Session ID from push notification
	Signature string `json:"signature"`  // HMAC-SHA256(challenge:sessionId:timestamp)
	Timestamp int64  `json:"timestamp"`  // Unix timestamp
}

type TunnelRequest struct {
	ServerID       string `msgpack:"serverId"`
	ServerSecret   string `msgpack:"serverSecret"`
	SessionID      string `msgpack:"sessionId"`
	Challenge      string `msgpack:"challenge"`
	TunnelEndpoint string `msgpack:"tunnelEndpoint"`
	Timestamp      string `msgpack:"timestamp"`
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

		if err := packer.UnpackMessage(msg.Data, &req); err != nil {
			proxyClient.RespondError(msg, err.Error())
			return
		}

		// Handle connection
		if err := handleConnect(req); err != nil {
			proxyClient.RespondError(msg, err.Error())
		} else {
			proxyClient.RespondSuccess(msg, map[string]interface{}{
				"connected": true,
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
	// Close existing tunnel if any
	if currentTunnel != nil {
		currentTunnel.Close()
	}

	log.Logger.Debug().Msg("New tunnel connection request")

	// Create new tunnel connection
	currentTunnel = NewTunnelConnection(
		req.ServerID,
		req.ServerSecret,
		req.SessionID,
		req.Challenge,
		req.TunnelEndpoint,
	)

	// Set up event handlers for tunnel lifecycle
	currentTunnel.OnConnected = func() {
		// Tunnel established successfully
		log.Logger.Debug().Msg("Tunnel connection established")
	}

	currentTunnel.OnDisconnected = func(reason string) {
		// Tunnel disconnected
		log.Logger.Debug().Str("reason", reason).Msg("Tunnel connection closed")
	}

	currentTunnel.OnError = func(err error) {
		// Handle tunnel errors silently in production
		log.Logger.Error().Err(err).Msg("Tunnel connection error")
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

// Connect establishes a tunnel connection to the proxy server.
// Steps:
// 1. Parse endpoint URL and determine correct port (443 for HTTPS, custom port, etc)
// 2. Establish TLS connection (with self-signed cert support)
// 3. Send authentication frame with HMAC signature
// 4. Create YAMUX session for stream multiplexing
// 5. Start accepting incoming streams from the proxy
func (t *TunnelConnection) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Parse endpoint URL to extract host and determine port
	var host, port, address string

	// Try to parse as URL first
	if u, err := url.Parse(t.Endpoint); err == nil && u.Scheme != "" {
		host = u.Hostname()
		port = u.Port()
		if port == "" {
			// Use default ports based on scheme
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		address = net.JoinHostPort(host, port)
	} else {
		// Try to parse as host:port
		var err error
		host, _, err = net.SplitHostPort(t.Endpoint)
		if err != nil {
			// No port specified, assume it's just a hostname
			host = t.Endpoint
			address = net.JoinHostPort(host, "9092")
		} else {
			// Valid host:port format
			address = t.Endpoint
		}
	}

	// Connect with TLS
	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", address, err)
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

	// Send authentication frame to establish tunnel

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

// handleStream processes an incoming request stream from the proxy.
// It uses httputil.ReverseProxy for robust HTTP handling:
// - Parses the incoming HTTP request
// - Forwards to local camera.ui server (with HTTPS support)
// - Handles special cases like WebSocket upgrades
// - Writes response back through the YAMUX stream
func (t *TunnelConnection) handleStream(stream net.Conn) {
	defer stream.Close()

	// Read the HTTP request from the stream
	reader := bufio.NewReader(stream)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to read request from stream: %w", err))
		}
		return
	}

	// Check if this is a WebSocket upgrade request
	if isWebSocketRequest(req) {
		t.handleWebSocketStream(stream, req, reader)
		return
	}

	// Create target URL
	target, err := url.Parse(fmt.Sprintf("https://localhost:%s", t.LocalPort))
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to parse target URL: %w", err))
		}
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Configure transport for self-signed certificates
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Log errors from the proxy
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("proxy error: %w", err))
		}
		// Write error response
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "Bad Gateway: %v", err)
	}

	// Use default proxy director

	// Create a response writer that writes to the stream
	rw := &streamResponseWriter{
		stream: stream,
		header: make(http.Header),
	}

	// Serve the request through the proxy
	proxy.ServeHTTP(rw, req)

	// Request proxied successfully
}

// isWebSocketRequest checks if the request is a WebSocket upgrade
func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocketStream handles WebSocket connections that require special processing.
// WebSocket connections can't use httputil.ReverseProxy because they need:
// - Direct TCP connection after protocol upgrade
// - Bidirectional streaming without HTTP framing
// - Proper handling of the connection hijacking process
// This function manually forwards the upgrade and establishes a TCP tunnel.
func (t *TunnelConnection) handleWebSocketStream(stream net.Conn, req *http.Request, reader *bufio.Reader) {
	// Create target URL for WebSocket
	targetURL := fmt.Sprintf("wss://localhost:%s%s", t.LocalPort, req.URL.Path)
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	// Connect to local WebSocket server
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	localConn, err := dialer.Dial("tcp", fmt.Sprintf("localhost:%s", t.LocalPort))
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to connect to local WebSocket server: %w", err))
		}
		// Send error response
		stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer localConn.Close()

	// Forward the upgrade request
	if err := req.Write(localConn); err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to forward WebSocket request: %w", err))
		}
		stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Read the upgrade response
	localReader := bufio.NewReader(localConn)
	resp, err := http.ReadResponse(localReader, req)
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to read WebSocket response: %w", err))
		}
		stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Forward the response back to stream
	if err := resp.Write(stream); err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to forward WebSocket response: %w", err))
		}
		return
	}

	// If upgrade was successful, start bidirectional copy
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// WebSocket upgrade successful

		// Copy any buffered data
		if reader.Buffered() > 0 {
			io.CopyN(localConn, reader, int64(reader.Buffered()))
		}
		if localReader.Buffered() > 0 {
			io.CopyN(stream, localReader, int64(localReader.Buffered()))
		}

		// Start bidirectional copy
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(localConn, stream)
			localConn.Close()
		}()

		go func() {
			defer wg.Done()
			io.Copy(stream, localConn)
			stream.Close()
		}()

		wg.Wait()
	}
}

// streamResponseWriter implements http.ResponseWriter for a net.Conn stream
type streamResponseWriter struct {
	stream      net.Conn
	header      http.Header
	wroteHeader bool
	statusCode  int
}

func (w *streamResponseWriter) Header() http.Header {
	return w.header
}

func (w *streamResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.stream.Write(data)
}

func (w *streamResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = statusCode

	// Write status line
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	w.stream.Write([]byte(statusLine))

	// Write headers
	for key, values := range w.header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", key, value)
			w.stream.Write([]byte(headerLine))
		}
	}

	// End headers
	w.stream.Write([]byte("\r\n"))
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
