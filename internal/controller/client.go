package controller

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

var ErrUnexpectedResponse = errors.New("unexpected management response")
var ErrCoreRejectedRequest = errors.New("core rejected management request")

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

// RegisterPeer sends an approved peer without transferring private key material.
func (client Client) RegisterPeer(requestID uint64, peer protocol.PeerRegistration) (protocol.ManagementResponse, error) {
	payload, err := protocol.MarshalPeerRegistration(peer)
	if err != nil {
		return protocol.ManagementResponse{}, err
	}
	return client.callSuccessful(protocol.ManagementRequest{
		Version: protocol.ManagementVersion, RequestID: requestID,
		Operation: protocol.OperationRegisterPeer, Payload: payload,
	})
}

// RemovePeer revokes a peer approval in the Rust Core.
func (client Client) RemovePeer(requestID uint64, peerID uint64) (protocol.ManagementResponse, error) {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, peerID)
	return client.callSuccessful(protocol.ManagementRequest{
		Version: protocol.ManagementVersion, RequestID: requestID,
		Operation: protocol.OperationRemovePeer, Payload: payload,
	})
}

func (client Client) Initialize(requestID uint64) (protocol.ManagementResponse, error) {
	return client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationInitialize})
}

func (client Client) Start(requestID uint64) (protocol.ManagementResponse, error) {
	return client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationStart})
}

func (client Client) Stop(requestID uint64) (protocol.ManagementResponse, error) {
	return client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationStop})
}

// GetMetrics retrieves the secret-free Core counters.
func (client Client) GetMetrics(requestID uint64) (protocol.MetricsSnapshot, error) {
	response, err := client.callSuccessful(protocol.ManagementRequest{
		Version: protocol.ManagementVersion, RequestID: requestID,
		Operation: protocol.OperationGetMetrics,
	})
	if err != nil {
		return protocol.MetricsSnapshot{}, err
	}
	return protocol.UnmarshalMetrics(response.Payload)
}

func (client Client) CreateSession(requestID uint64, session protocol.SessionRequest) (protocol.SessionStatus, error) {
	response, err := client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationCreateSession, Payload: session.MarshalBinary()})
	if err != nil {
		return protocol.SessionStatus{}, err
	}
	return protocol.UnmarshalSessionStatus(response.Payload)
}

func (client Client) GetSession(requestID uint64, sessionID uint32) (protocol.SessionStatus, error) {
	response, err := client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationGetSession, Payload: (protocol.SessionRequest{SessionID: sessionID}).MarshalBinary()})
	if err != nil {
		return protocol.SessionStatus{}, err
	}
	return protocol.UnmarshalSessionStatus(response.Payload)
}

func (client Client) TerminateSession(requestID uint64, sessionID uint32) (protocol.ManagementResponse, error) {
	return client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationTerminateSession, Payload: (protocol.SessionRequest{SessionID: sessionID}).MarshalBinary()})
}

func (client Client) UpdateConfiguration(requestID uint64, configuration protocol.NetworkConfiguration) (protocol.ManagementResponse, error) {
	return client.callSuccessful(protocol.ManagementRequest{Version: protocol.ManagementVersion, RequestID: requestID, Operation: protocol.OperationUpdateConfiguration, Payload: configuration.MarshalBinary()})
}

func (client Client) callSuccessful(request protocol.ManagementRequest) (protocol.ManagementResponse, error) {
	response, err := client.Call(request)
	if err != nil {
		return protocol.ManagementResponse{}, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return response, fmt.Errorf("%w: status=%d error=%d", ErrCoreRejectedRequest, response.Status, response.ErrorCode)
	}
	return response, nil
}
