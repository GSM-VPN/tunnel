package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ManagementVersion is the version of the Go-Rust control-plane message format.
const ManagementVersion uint16 = 1

const (
	managementFrameHeaderSize = 4
	managementRequestSize     = 2 + 8 + 2 + 4
	managementResponseSize    = 2 + 8 + 2 + 2 + 4
	MaxManagementFrameSize    = 1 << 20
)

const managementSessionPayloadSize = 12

var (
	ErrManagementFrameTooLarge  = errors.New("management frame exceeds maximum size")
	ErrManagementFrameMalformed = errors.New("malformed management frame")
	ErrUnknownOperation         = errors.New("unknown management operation")
)

// Operation identifies a controller request without carrying data-plane keys.
type Operation uint16

const (
	OperationInitialize Operation = iota + 1
	OperationStart
	OperationStop
	OperationRegisterPeer
	OperationRemovePeer
	OperationCreateSession
	OperationTerminateSession
	OperationGetSession
	OperationListSessions
	OperationGetMetrics
	OperationUpdateConfiguration
	OperationHealth
)

func (operation Operation) IsValid() bool {
	return operation >= OperationInitialize && operation <= OperationHealth
}

// ManagementRequest contains only control-plane metadata and opaque operation payload.
// Key material must never be represented by this type.
type ManagementRequest struct {
	Version   uint16
	RequestID uint64
	Operation Operation
	Payload   []byte
}

// ManagementResponse contains a request result and an optional operation payload.
type ManagementResponse struct {
	Version   uint16
	RequestID uint64
	Status    uint16
	ErrorCode uint16
	Payload   []byte
}

// SessionRequest identifies a peer session for create, get, and terminate operations.
type SessionRequest struct {
	SessionID uint32
	PeerID    uint64
}

// SessionStatus is the non-secret session state returned by the Core.
type SessionStatus struct {
	SessionID uint32
	PeerID    uint64
	State     byte
}

// MetricsSnapshot is the secret-free Core metrics payload returned over IPC.
type MetricsSnapshot struct {
	ActiveSessions         uint64
	TxBytes                uint64
	RxBytes                uint64
	TxPackets              uint64
	RxPackets              uint64
	AuthenticationFailures uint64
	ReplayRejections       uint64
	Reconnects             uint64
	HandshakeFailures      uint64
	KeepaliveFailures      uint64
	PacketErrors           uint64
}

// UnmarshalMetrics decodes the fixed eleven-counter Core metrics payload.
func UnmarshalMetrics(payload []byte) (MetricsSnapshot, error) {
	if len(payload) != 11*8 {
		return MetricsSnapshot{}, fmt.Errorf("invalid metrics payload length: %d", len(payload))
	}
	values := make([]uint64, 11)
	for index := range values {
		values[index] = binary.BigEndian.Uint64(payload[index*8:])
	}
	return MetricsSnapshot{
		ActiveSessions: values[0], TxBytes: values[1], RxBytes: values[2],
		TxPackets: values[3], RxPackets: values[4], AuthenticationFailures: values[5],
		ReplayRejections: values[6], Reconnects: values[7], HandshakeFailures: values[8],
		KeepaliveFailures: values[9], PacketErrors: values[10],
	}, nil
}

// NetworkConfiguration contains the mutable network policy accepted by Core.
type NetworkConfiguration struct {
	UDPPort    uint16
	MTU        uint16
	DualStack  bool
	KillSwitch bool
}

func (configuration NetworkConfiguration) MarshalBinary() []byte {
	payload := make([]byte, 10)
	payload[0] = 16 // IPv4 network is fixed at 10.80.0.0/16.
	payload[1] = 64 // IPv6 network is fixed at fd80:1234:5678::/64.
	binary.BigEndian.PutUint16(payload[2:4], configuration.UDPPort)
	binary.BigEndian.PutUint16(payload[4:6], configuration.MTU)
	if configuration.DualStack {
		payload[6] = 1
	}
	if configuration.KillSwitch {
		payload[7] = 1
	}
	return payload
}

func (request SessionRequest) MarshalBinary() []byte {
	payload := make([]byte, managementSessionPayloadSize)
	binary.BigEndian.PutUint32(payload[0:4], request.SessionID)
	binary.BigEndian.PutUint64(payload[4:12], request.PeerID)
	return payload
}

func UnmarshalSessionStatus(payload []byte) (SessionStatus, error) {
	if len(payload) != managementSessionPayloadSize+1 {
		return SessionStatus{}, fmt.Errorf("invalid session status length: %d", len(payload))
	}
	return SessionStatus{
		SessionID: binary.BigEndian.Uint32(payload[0:4]),
		PeerID:    binary.BigEndian.Uint64(payload[4:12]),
		State:     payload[12],
	}, nil
}

// MarshalFrame encodes a request with a four-byte big-endian frame length.
func (request ManagementRequest) MarshalFrame() ([]byte, error) {
	if request.Version == 0 {
		return nil, fmt.Errorf("%w: zero request version", ErrManagementFrameMalformed)
	}
	if !request.Operation.IsValid() {
		return nil, ErrUnknownOperation
	}
	if len(request.Payload) > MaxManagementFrameSize-managementRequestSize-managementFrameHeaderSize {
		return nil, ErrManagementFrameTooLarge
	}
	frameLength := managementRequestSize + len(request.Payload)
	frame := make([]byte, managementFrameHeaderSize+frameLength)
	binary.BigEndian.PutUint32(frame[:managementFrameHeaderSize], uint32(frameLength))
	offset := managementFrameHeaderSize
	binary.BigEndian.PutUint16(frame[offset:], request.Version)
	offset += 2
	binary.BigEndian.PutUint64(frame[offset:], request.RequestID)
	offset += 8
	binary.BigEndian.PutUint16(frame[offset:], uint16(request.Operation))
	offset += 2
	binary.BigEndian.PutUint32(frame[offset:], uint32(len(request.Payload)))
	offset += 4
	copy(frame[offset:], request.Payload)
	return frame, nil
}

// UnmarshalRequestFrame decodes exactly one length-prefixed request.
func UnmarshalRequestFrame(frame []byte) (ManagementRequest, error) {
	if err := validateFrame(frame, managementRequestSize); err != nil {
		return ManagementRequest{}, err
	}
	payloadLength := int(binary.BigEndian.Uint32(frame[managementFrameHeaderSize+12:]))
	if payloadLength != len(frame)-managementFrameHeaderSize-managementRequestSize {
		return ManagementRequest{}, fmt.Errorf("%w: request payload length", ErrManagementFrameMalformed)
	}
	offset := managementFrameHeaderSize
	request := ManagementRequest{
		Version:   binary.BigEndian.Uint16(frame[offset:]),
		RequestID: binary.BigEndian.Uint64(frame[offset+2:]),
		Operation: Operation(binary.BigEndian.Uint16(frame[offset+10:])),
		Payload:   append([]byte(nil), frame[offset+managementRequestSize:]...),
	}
	if request.Version == 0 {
		return ManagementRequest{}, fmt.Errorf("%w: zero request version", ErrManagementFrameMalformed)
	}
	if !request.Operation.IsValid() {
		return ManagementRequest{}, ErrUnknownOperation
	}
	return request, nil
}

// MarshalFrame encodes a response with a four-byte big-endian frame length.
func (response ManagementResponse) MarshalFrame() ([]byte, error) {
	if response.Version == 0 {
		return nil, fmt.Errorf("%w: zero response version", ErrManagementFrameMalformed)
	}
	if len(response.Payload) > MaxManagementFrameSize-managementResponseSize-managementFrameHeaderSize {
		return nil, ErrManagementFrameTooLarge
	}
	frameLength := managementResponseSize + len(response.Payload)
	frame := make([]byte, managementFrameHeaderSize+frameLength)
	binary.BigEndian.PutUint32(frame[:managementFrameHeaderSize], uint32(frameLength))
	offset := managementFrameHeaderSize
	binary.BigEndian.PutUint16(frame[offset:], response.Version)
	offset += 2
	binary.BigEndian.PutUint64(frame[offset:], response.RequestID)
	offset += 8
	binary.BigEndian.PutUint16(frame[offset:], response.Status)
	offset += 2
	binary.BigEndian.PutUint16(frame[offset:], response.ErrorCode)
	offset += 2
	binary.BigEndian.PutUint32(frame[offset:], uint32(len(response.Payload)))
	offset += 4
	copy(frame[offset:], response.Payload)
	return frame, nil
}

// UnmarshalResponseFrame decodes exactly one length-prefixed response.
func UnmarshalResponseFrame(frame []byte) (ManagementResponse, error) {
	if err := validateFrame(frame, managementResponseSize); err != nil {
		return ManagementResponse{}, err
	}
	payloadLength := int(binary.BigEndian.Uint32(frame[managementFrameHeaderSize+14:]))
	if payloadLength != len(frame)-managementFrameHeaderSize-managementResponseSize {
		return ManagementResponse{}, fmt.Errorf("%w: response payload length", ErrManagementFrameMalformed)
	}
	offset := managementFrameHeaderSize
	response := ManagementResponse{
		Version:   binary.BigEndian.Uint16(frame[offset:]),
		RequestID: binary.BigEndian.Uint64(frame[offset+2:]),
		Status:    binary.BigEndian.Uint16(frame[offset+10:]),
		ErrorCode: binary.BigEndian.Uint16(frame[offset+12:]),
		Payload:   append([]byte(nil), frame[offset+managementResponseSize:]...),
	}
	if response.Version == 0 {
		return ManagementResponse{}, fmt.Errorf("%w: zero response version", ErrManagementFrameMalformed)
	}
	return response, nil
}

func validateFrame(frame []byte, minimumPayload int) error {
	if len(frame) < managementFrameHeaderSize+minimumPayload {
		return fmt.Errorf("%w: frame is truncated", ErrManagementFrameMalformed)
	}
	declared := int(binary.BigEndian.Uint32(frame[:managementFrameHeaderSize]))
	if declared > MaxManagementFrameSize {
		return ErrManagementFrameTooLarge
	}
	if declared != len(frame)-managementFrameHeaderSize {
		return fmt.Errorf("%w: frame length", ErrManagementFrameMalformed)
	}
	return nil
}
