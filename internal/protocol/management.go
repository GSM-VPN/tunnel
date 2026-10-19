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

var (
	ErrManagementFrameTooLarge  = errors.New("management frame exceeds maximum size")
	ErrManagementFrameMalformed = errors.New("malformed management frame")
)

// Operation identifies a controller request without carrying data-plane keys.
type Operation uint16

const (
	OperationHealth Operation = iota + 1
	OperationStart
	OperationStop
	OperationGetMetrics
)

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

// MarshalFrame encodes a request with a four-byte big-endian frame length.
func (request ManagementRequest) MarshalFrame() ([]byte, error) {
	if request.Version == 0 {
		return nil, fmt.Errorf("%w: zero request version", ErrManagementFrameMalformed)
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
	return ManagementResponse{
		Version:   binary.BigEndian.Uint16(frame[offset:]),
		RequestID: binary.BigEndian.Uint64(frame[offset+2:]),
		Status:    binary.BigEndian.Uint16(frame[offset+10:]),
		ErrorCode: binary.BigEndian.Uint16(frame[offset+12:]),
		Payload:   append([]byte(nil), frame[offset+managementResponseSize:]...),
	}, nil
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
