package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/seydx/cameraui.com/cloud-client/internal/app"
	"github.com/seydx/cameraui.com/cloud-client/internal/packer"
	"github.com/seydx/cameraui.com/cloud-client/pkg/log"
)

type Client struct {
	conn     *nats.Conn
	handlers map[string]nats.MsgHandler
}

type Response struct {
	Success bool        `msgpack:"success"`
	Data    interface{} `msgpack:"data,omitempty"`
	Error   string      `msgpack:"error,omitempty"`
}

var GlobalClient *Client

func Init() {
	client, err := connect()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("Failed to connect to camera.ui server")
	}

	GlobalClient = client
}

func GetClient() *Client {
	return GlobalClient
}

func (c *Client) RegisterHandler(subject string, handler nats.MsgHandler) error {
	sub, err := c.conn.Subscribe(subject, handler)
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
	}

	// Set queue group to allow load balancing
	sub.SetPendingLimits(-1, -1) // unlimited pending msgs

	c.handlers[subject] = handler

	return nil
}

func (c *Client) RegisterQueueHandler(subject, queue string, handler nats.MsgHandler) error {
	sub, err := c.conn.QueueSubscribe(subject, queue, handler)
	if err != nil {
		return fmt.Errorf("failed to queue subscribe to %s: %w", subject, err)
	}

	sub.SetPendingLimits(-1, -1)

	c.handlers[subject] = handler

	return nil
}

func (c *Client) Publish(subject string, data interface{}) error {
	packed, err := packer.PackMessage(data)
	if err != nil {
		return fmt.Errorf("failed to pack message: %w", err)
	}

	return c.conn.Publish(subject, packed)
}

func (c *Client) Request(subject string, data interface{}, timeout time.Duration) (*Response, error) {
	packed, err := packer.PackMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to pack request: %w", err)
	}

	var response Response

	responseMsg, err := c.conn.Request(subject, packed, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to request %s: %w", subject, err)
	}

	if err := packer.UnpackMessage(responseMsg.Data, &response); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("request failed: %s", response.Error)
	}

	return &response, nil
}

func (c *Client) RequestWithContext(ctx context.Context, subject string, data interface{}) (*Response, error) {
	packed, err := packer.PackMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to pack request: %w", err)
	}

	var response Response

	responseMsg, err := c.conn.RequestWithContext(ctx, subject, packed)
	if err != nil {
		return nil, fmt.Errorf("failed to request %s: %w", subject, err)
	}

	if err := packer.UnpackMessage(responseMsg.Data, &response); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	return &response, nil
}

func (c *Client) Respond(msg *nats.Msg, data interface{}) error {
	if msg.Reply == "" {
		return fmt.Errorf("no reply subject in message")
	}

	packed, err := packer.PackMessage(data)
	if err != nil {
		return fmt.Errorf("failed to pack response: %w", err)
	}

	return c.conn.Publish(msg.Reply, packed)
}

func (c *Client) RespondError(msg *nats.Msg, message string) error {
	response := Response{
		Success: false,
		Error:   message,
	}
	return c.Respond(msg, response)
}

func (c *Client) RespondSuccess(msg *nats.Msg, data interface{}) error {
	response := Response{
		Success: true,
		Data:    data,
	}
	return c.Respond(msg, response)
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) IsConnected() bool {
	return c.conn != nil && c.conn.IsConnected()
}

func (c *Client) GetStats() nats.Statistics {
	if c.conn == nil {
		return nats.Statistics{}
	}
	return c.conn.Stats()
}

func (c *Client) Flush() error {
	if c.conn == nil {
		return fmt.Errorf("no connection")
	}
	return c.conn.Flush()
}

func (c *Client) FlushTimeout(timeout time.Duration) error {
	if c.conn == nil {
		return fmt.Errorf("no connection")
	}
	return c.conn.FlushTimeout(timeout)
}

func connect() (*Client, error) {
	cfg := app.GetConfig()

	opts := []nats.Option{
		nats.Name("camera.ui cloud"),
		nats.UserInfo(cfg.NATSUser, cfg.NATSPassword),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1), // infinite reconnects
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				log.Logger.Warn().Err(err).Msg("Proxy disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Logger.Info().Str("url", nc.ConnectedUrl()).Msg("Proxy reconnected")
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			log.Logger.Info().Msg("Proxy connection closed")
		}),
	}

	var conn *nats.Conn
	var err error

	for _, endpoint := range cfg.NATSEndpoints {
		conn, err = nats.Connect(endpoint, opts...)
		if err == nil {
			break
		}
	}

	if conn == nil {
		return nil, fmt.Errorf("failed to connect to camera.ui server: %w", err)
	}

	client := &Client{
		conn:     conn,
		handlers: make(map[string]nats.MsgHandler),
	}

	return client, nil
}
