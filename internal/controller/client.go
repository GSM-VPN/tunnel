package controller

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

var ErrUnexpectedResponse = errors.New("unexpected management response")

// Client sends control-plane requests over a local Unix Domain Socket.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// Call opens one short-lived local IPC connection and waits for one response.
func (client Client) Call(request protocol.ManagementRequest) (protocol.ManagementResponse, error) {
	if client.SocketPath == "" {
		return protocol.ManagementResponse{}, errors.New("socket path is required")
	}
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	connection, err := net.DialTimeout("unix", client.SocketPath, timeout)
	if err != nil {
		return protocol.ManagementResponse{}, fmt.Errorf("connect to core IPC: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	frame, err := request.MarshalFrame()
	if err != nil {
		return protocol.ManagementResponse{}, err
	}
	if _, err := connection.Write(frame); err != nil {
		return protocol.ManagementResponse{}, fmt.Errorf("write core IPC request: %w", err)
	}
	responseFrame, err := readFrame(connection)
	if err != nil {
		return protocol.ManagementResponse{}, fmt.Errorf("read core IPC response: %w", err)
	}
	response, err := protocol.UnmarshalResponseFrame(responseFrame)
	if err != nil {
		return protocol.ManagementResponse{}, err
	}
	if response.Version != request.Version || response.RequestID != request.RequestID {
		return protocol.ManagementResponse{}, fmt.Errorf("%w: version or request ID mismatch", ErrUnexpectedResponse)
	}
	return response, nil
}
