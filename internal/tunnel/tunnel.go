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

// TunnelConnection owns one outbound TLS+yamux session to the cloud tunnel
// endpoint. Lifecycle: NewTunnelConnection → Connect → (streams handled in
// background) → Close. The OnConnected / OnDisconnected / OnError callbacks
// fire from the goroutine that observes the event; callers must keep them
// thread-safe.
type TunnelConnection struct {
	ServerID     string
	ServerSecret string
	SessionID    string
	Challenge    string
	Endpoint     string
	LocalPort    string

	conn        net.Conn
	session     *yamux.Session
	connected   atomic.Bool
	ConnectedAt time.Time
	mu          sync.Mutex

	OnConnected    func()
	OnDisconnected func(reason string)
	OnError        func(error)
}

// AuthFrame is the JSON envelope sent over the freshly opened TLS connection
// to authenticate with the tunnel server.
type AuthFrame struct {
	Type      string `json:"type"`
	ServerID  string `json:"server_id"`
	SessionID string `json:"session_id"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// TunnelRequest is the inbound NATS message that triggers a new tunnel.
type TunnelRequest struct {
	ServerID       string `msgpack:"serverId"`
	ServerSecret   string `msgpack:"serverSecret"`
	SessionID      string `msgpack:"sessionId"`
	Challenge      string `msgpack:"challenge"`
	TunnelEndpoint string `msgpack:"tunnelEndpoint"`
	Timestamp      string `msgpack:"timestamp"`
}

var (
	// currentTunnel is the active tunnel (if any). Always go through
	// swapCurrentTunnel / getCurrentTunnel — the NATS handlers run on
	// independent goroutines per subject, so direct access races.
	currentTunnel   *TunnelConnection
	currentTunnelMu sync.Mutex

	ConnectSubject    = "cloud.tunnel.connect"
	DisconnectSubject = "cloud.tunnel.disconnect"
	StatusSubject     = "cloud.tunnel.status"
)

// Init registers the NATS handlers that drive the tunnel lifecycle
// (connect / disconnect / status). Calls log.Fatal if registration fails.
func Init() {
	proxyClient := proxy.GetClient()
	if proxyClient == nil {
		log.Logger.Fatal().Msg("Proxy client is not initialized")
	}

	if err := proxyClient.RegisterHandler(ConnectSubject, func(msg *nats.Msg) {
		var req TunnelRequest

		if err := packer.UnpackMessage(msg.Data, &req); err != nil {
			respondError(proxyClient, msg, err.Error())
			return
		}

		if err := handleConnect(&req); err != nil {
			respondError(proxyClient, msg, err.Error())
		} else {
			respondSuccess(proxyClient, msg, map[string]any{
				"status": "connected",
			})
		}
	}); err != nil {
		log.Logger.Fatal().Err(err).Str("subject", ConnectSubject).Msg("Failed to register handler")
	}

	if err := proxyClient.RegisterHandler(DisconnectSubject, func(msg *nats.Msg) {
		if old := swapCurrentTunnel(nil); old != nil {
			old.Close()
		}

		respondSuccess(proxyClient, msg, map[string]any{
			"status": "disconnected",
		})
	}); err != nil {
		log.Logger.Fatal().Err(err).Str("subject", DisconnectSubject).Msg("Failed to register handler")
	}

	if err := proxyClient.RegisterHandler(StatusSubject, func(msg *nats.Msg) {
		tunnel := getCurrentTunnel()
		if tunnel == nil || !tunnel.IsConnected() {
			respondSuccess(proxyClient, msg, map[string]any{
				"status": "disconnected",
			})
			return
		}

		respondSuccess(proxyClient, msg, tunnel.StatusSnapshot())
	}); err != nil {
		log.Logger.Fatal().Err(err).Str("subject", StatusSubject).Msg("Failed to register handler")
	}
}

// NewTunnelConnection builds an unconnected TunnelConnection populated from
// the request fields plus the process-wide local port.
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

// Connect dials the tunnel endpoint over TLS, authenticates with an HMAC-signed
// frame, and starts a yamux client session. The session's accept loop runs in a
// background goroutine until disconnect.
func (t *TunnelConnection) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var host, port, address string

	if u, err := url.Parse(t.Endpoint); err == nil && u.Scheme != "" {
		host = u.Hostname()
		port = u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		address = net.JoinHostPort(host, port)
	} else {
		var err error
		host, _, err = net.SplitHostPort(t.Endpoint)
		if err != nil {
			// No port specified, assume t.Endpoint is just a hostname.
			host = t.Endpoint
			address = net.JoinHostPort(host, "9092")
		} else {
			address = t.Endpoint
		}
	}

	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", address, err)
	}

	t.conn = conn

	authFrame := &AuthFrame{
		Type:      "AUTH",
		ServerID:  t.ServerID,
		SessionID: t.SessionID,
		Timestamp: time.Now().Unix(),
	}

	payload := fmt.Sprintf("%s:%s:%d", t.Challenge, t.SessionID, authFrame.Timestamp)
	authFrame.Signature = t.calculateHMAC(payload)

	authJSON, err := json.Marshal(authFrame)
	if err != nil {
		closeConnLog(conn, "auth marshal failure")
		return fmt.Errorf("failed to marshal auth frame: %w", err)
	}

	if _, err := conn.Write(append(authJSON, '\n')); err != nil {
		closeConnLog(conn, "auth write failure")
		return fmt.Errorf("failed to send auth frame: %w", err)
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		closeConnLog(conn, "auth read failure")
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	response = strings.TrimSpace(response)
	if response != "OK" {
		closeConnLog(conn, "auth rejected")
		return fmt.Errorf("authentication failed: %s", response)
	}

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.AcceptBacklog = 256
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = 30 * time.Second
	yamuxConfig.MaxStreamWindowSize = 256 * 1024
	yamuxConfig.LogOutput = io.Discard

	session, err := yamux.Client(conn, yamuxConfig)
	if err != nil {
		closeConnLog(conn, "yamux session failure")
		return fmt.Errorf("failed to create yamux session: %w", err)
	}

	t.session = session
	t.connected.Store(true)
	t.ConnectedAt = time.Now()

	// Pass the session as parameter — the goroutine keeps its own local
	// reference, immune to a concurrent disconnect() that nils t.session.
	// Reading the field directly inside the loop is racy and crashes with a
	// nil-deref when the connection is torn down between iterations.
	go t.acceptStreams(session)

	if t.OnConnected != nil {
		t.OnConnected()
	}

	return nil
}

// Close tears down the tunnel and fires OnDisconnected with reason
// "closed by user".
func (t *TunnelConnection) Close() {
	t.disconnect("closed by user")
}

func (t *TunnelConnection) IsConnected() bool {
	return t.connected.Load()
}

// StatusSnapshot returns the connected status payload read under the mutex,
// so a concurrent disconnect() can't nil t.session between the connected check
// and the NumStreams() call.
func (t *TunnelConnection) StatusSnapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := map[string]any{
		"status":       "connected",
		"connected_at": t.ConnectedAt.UnixMilli(),
	}

	if t.session != nil {
		result["active_streams"] = t.session.NumStreams()
	}

	return result
}

// respondError logs the publish failure — there's no useful recovery from
// inside a NATS handler if the response can't be sent (the requester will
// time out anyway), but a silent drop hides bugs.
func respondError(client *proxy.Client, msg *nats.Msg, message string) {
	if err := client.RespondError(msg, message); err != nil {
		log.Logger.Error().Err(err).Str("subject", msg.Subject).Msg("Failed to send error response")
	}
}

func respondSuccess(client *proxy.Client, msg *nats.Msg, data any) {
	if err := client.RespondSuccess(msg, data); err != nil {
		log.Logger.Error().Err(err).Str("subject", msg.Subject).Msg("Failed to send success response")
	}
}

func handleConnect(req *TunnelRequest) error {
	log.Logger.Debug().Msg("New tunnel connection request")

	newTunnel := NewTunnelConnection(
		req.ServerID,
		req.ServerSecret,
		req.SessionID,
		req.Challenge,
		req.TunnelEndpoint,
	)

	newTunnel.OnConnected = func() {
		log.Logger.Debug().Msg("Tunnel connection established")
	}

	newTunnel.OnDisconnected = func(reason string) {
		log.Logger.Debug().Str("reason", reason).Msg("Tunnel connection closed")
	}

	newTunnel.OnError = func(err error) {
		log.Logger.Error().Err(err).Msg("Tunnel connection error")
	}

	// Install the new tunnel atomically before closing the old one — a status
	// request that races in between will see the new tunnel (still connecting,
	// IsConnected = false) rather than a stale closed pointer.
	if old := swapCurrentTunnel(newTunnel); old != nil {
		old.Close()
	}

	return newTunnel.Connect()
}

func swapCurrentTunnel(next *TunnelConnection) (previous *TunnelConnection) {
	currentTunnelMu.Lock()
	defer currentTunnelMu.Unlock()
	previous = currentTunnel
	currentTunnel = next
	return previous
}

func getCurrentTunnel() *TunnelConnection {
	currentTunnelMu.Lock()
	defer currentTunnelMu.Unlock()
	return currentTunnel
}

func (t *TunnelConnection) acceptStreams(session *yamux.Session) {
	defer t.disconnect("session closed")

	for {
		stream, err := session.Accept()
		if err != nil {
			if t.connected.Load() && t.OnError != nil {
				t.OnError(fmt.Errorf("failed to accept stream: %w", err))
			}
			return
		}

		go t.handleStream(stream)
	}
}

func (t *TunnelConnection) handleStream(stream net.Conn) {
	defer t.closeStream(stream, "handleStream done")

	reader := bufio.NewReader(stream)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to read request from stream: %w", err))
		}
		return
	}

	if isWebSocketRequest(req) {
		t.handleWebSocketStream(stream, req, reader)
		return
	}

	target, err := url.Parse(fmt.Sprintf("https://localhost:%s", t.LocalPort))
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to parse target URL: %w", err))
		}
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Backend uses self-signed certs — skip verification on the proxy hop.
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("proxy error: %w", err))
		}
		w.WriteHeader(http.StatusBadGateway)
		if _, writeErr := fmt.Fprintf(w, "Bad Gateway: %v", err); writeErr != nil && t.OnError != nil {
			t.OnError(fmt.Errorf("failed to write proxy error response: %w", writeErr))
		}
	}

	rw := &streamResponseWriter{
		stream: stream,
		header: make(http.Header),
	}

	proxy.ServeHTTP(rw, req)
}

func (t *TunnelConnection) handleWebSocketStream(stream net.Conn, req *http.Request, reader *bufio.Reader) {
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
		t.writeBadGateway(stream)
		return
	}
	defer t.closeConn(localConn, "WebSocket session done")

	if err := req.Write(localConn); err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to forward WebSocket request: %w", err))
		}
		t.writeBadGateway(stream)
		return
	}

	localReader := bufio.NewReader(localConn)
	resp, err := http.ReadResponse(localReader, req)
	if err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to read WebSocket response: %w", err))
		}
		t.writeBadGateway(stream)
		return
	}

	if err := resp.Write(stream); err != nil {
		if t.OnError != nil {
			t.OnError(fmt.Errorf("failed to forward WebSocket response: %w", err))
		}
		return
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.pumpWebSocket(stream, localConn, reader, localReader)
	}
}

func (t *TunnelConnection) pumpWebSocket(stream net.Conn, localConn net.Conn, reader, localReader *bufio.Reader) {
	// Drain any data buffered by the readers before starting the bidirectional
	// pump — otherwise the first frame after the handshake can be dropped.
	if reader.Buffered() > 0 {
		if _, err := io.CopyN(localConn, reader, int64(reader.Buffered())); err != nil && t.OnError != nil {
			t.OnError(fmt.Errorf("failed to flush buffered upstream data: %w", err))
		}
	}
	if localReader.Buffered() > 0 {
		if _, err := io.CopyN(stream, localReader, int64(localReader.Buffered())); err != nil && t.OnError != nil {
			t.OnError(fmt.Errorf("failed to flush buffered downstream data: %w", err))
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(localConn, stream); err != nil && t.OnError != nil {
			t.OnError(fmt.Errorf("WebSocket upstream copy ended: %w", err))
		}
		t.closeConn(localConn, "WebSocket upstream closed")
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(stream, localConn); err != nil && t.OnError != nil {
			t.OnError(fmt.Errorf("WebSocket downstream copy ended: %w", err))
		}
		t.closeStream(stream, "WebSocket downstream closed")
	}()

	wg.Wait()
}

func (t *TunnelConnection) writeBadGateway(stream net.Conn) {
	if _, err := stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); err != nil && t.OnError != nil {
		t.OnError(fmt.Errorf("failed to write 502 response: %w", err))
	}
}

func (t *TunnelConnection) closeStream(stream net.Conn, reason string) {
	if err := stream.Close(); err != nil && t.OnError != nil {
		t.OnError(fmt.Errorf("failed to close stream (%s): %w", reason, err))
	}
}

func (t *TunnelConnection) closeConn(conn net.Conn, reason string) {
	if err := conn.Close(); err != nil && t.OnError != nil {
		t.OnError(fmt.Errorf("failed to close connection (%s): %w", reason, err))
	}
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
		if err := t.session.Close(); err != nil {
			log.Logger.Warn().Err(err).Msg("Failed to close yamux session")
		}
		t.session = nil
	}

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			log.Logger.Warn().Err(err).Msg("Failed to close tunnel connection")
		}
		t.conn = nil
	}

	if t.OnDisconnected != nil {
		t.OnDisconnected(reason)
	}
}

// closeConnLog is a package-level helper for Connect()'s error paths where
// no TunnelConnection.OnError callback is wired up yet. Distinct name from
// the (*TunnelConnection).closeConn method to avoid the easy footgun of
// thinking they're interchangeable.
func closeConnLog(conn net.Conn, reason string) {
	if err := conn.Close(); err != nil {
		log.Logger.Warn().Err(err).Str("reason", reason).Msg("Failed to close connection")
	}
}
