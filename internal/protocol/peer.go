package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	peerPayloadFixedSize = 8 + 32 + 1 + 4 + 16 + 8 + 2
	maxPeerUserIDLength  = 256
	peerFlagIPv4         = 1 << 0
	peerFlagIPv6         = 1 << 1
)

var (
	ErrPeerPayloadMalformed = errors.New("malformed peer payload")
	ErrPeerUserIDTooLong    = errors.New("peer user ID is too long")
	ErrPeerExpiryInvalid    = errors.New("peer expiry is invalid")
)

// PeerRegistration is the non-secret approval data sent to the Rust Core.
// Private keys and Gateway secrets are intentionally absent.
type PeerRegistration struct {
	PeerID    uint64
	UserID    string
	PublicKey [32]byte
	IPv4      [4]byte
	HasIPv4   bool
	IPv6      [16]byte
	HasIPv6   bool
	ExpiresAt time.Time
}

// MarshalPeerRegistration encodes the stable RegisterPeer payload.
func MarshalPeerRegistration(peer PeerRegistration) ([]byte, error) {
	if len(peer.UserID) == 0 || len(peer.UserID) > maxPeerUserIDLength {
		return nil, ErrPeerUserIDTooLong
	}
	if !peer.HasIPv4 && !peer.HasIPv6 {
		return nil, ErrPeerPayloadMalformed
	}
	if peer.ExpiresAt.Unix() <= 0 {
		return nil, ErrPeerExpiryInvalid
	}
	payload := make([]byte, peerPayloadFixedSize+len(peer.UserID))
	binary.BigEndian.PutUint64(payload[0:8], peer.PeerID)
	copy(payload[8:40], peer.PublicKey[:])
	if peer.HasIPv4 {
		payload[40] |= peerFlagIPv4
	}
	copy(payload[41:45], peer.IPv4[:])
	if peer.HasIPv6 {
		payload[40] |= peerFlagIPv6
	}
	copy(payload[45:61], peer.IPv6[:])
	binary.BigEndian.PutUint64(payload[61:69], uint64(peer.ExpiresAt.Unix()))
	binary.BigEndian.PutUint16(payload[69:71], uint16(len(peer.UserID)))
	copy(payload[71:], peer.UserID)
	return payload, nil
}

// UnmarshalPeerRegistration decodes and validates a RegisterPeer payload.
func UnmarshalPeerRegistration(payload []byte) (PeerRegistration, error) {
	if len(payload) < peerPayloadFixedSize {
		return PeerRegistration{}, ErrPeerPayloadMalformed
	}
	userLength := int(binary.BigEndian.Uint16(payload[69:71]))
	if userLength == 0 || userLength > maxPeerUserIDLength || len(payload) != peerPayloadFixedSize+userLength {
		return PeerRegistration{}, ErrPeerPayloadMalformed
	}
	flags := payload[40]
	if flags&^(peerFlagIPv4|peerFlagIPv6) != 0 || flags == 0 {
		return PeerRegistration{}, ErrPeerPayloadMalformed
	}
	peer := PeerRegistration{
		PeerID:    binary.BigEndian.Uint64(payload[0:8]),
		ExpiresAt: time.Unix(int64(binary.BigEndian.Uint64(payload[61:69])), 0),
		UserID:    string(payload[71:]),
		HasIPv4:   flags&peerFlagIPv4 != 0,
		HasIPv6:   flags&peerFlagIPv6 != 0,
	}
	copy(peer.PublicKey[:], payload[8:40])
	copy(peer.IPv4[:], payload[41:45])
	copy(peer.IPv6[:], payload[45:61])
	if peer.ExpiresAt.Unix() <= 0 {
		return PeerRegistration{}, ErrPeerExpiryInvalid
	}
	return peer, nil
}

func (peer PeerRegistration) String() string {
	return fmt.Sprintf("peer=%d", peer.PeerID)
}
