package controller

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

func readFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > protocol.MaxManagementFrameSize {
		return nil, fmt.Errorf("management frame exceeds maximum size: %d", length)
	}
	frame := make([]byte, 4+int(length))
	copy(frame, header[:])
	if _, err := io.ReadFull(reader, frame[4:]); err != nil {
		return nil, err
	}
	return frame, nil
}
