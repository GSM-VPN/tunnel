package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

var (
	ErrGatewaySecretRequired   = errors.New("gateway shared secret is required")
	ErrGatewaySignatureInvalid = errors.New("gateway signature is invalid")
	ErrApprovalInvalid         = errors.New("VPN approval is invalid")
	ErrApprovalServerMismatch  = errors.New("VPN approval belongs to another server")
	ErrPeerNotApproved         = errors.New("peer is not approved")
)

// GatewayAuthenticator verifies the service-plane HMAC used by vpn-server.
// The secret is held only by the caller and never included in IPC payloads.
type GatewayAuthenticator struct {
	secret []byte
}

// NewGatewayAuthenticator creates an HMAC verifier from a shared secret.
func NewGatewayAuthenticator(secret string) (GatewayAuthenticator, error) {
	if strings.TrimSpace(secret) == "" {
		return GatewayAuthenticator{}, ErrGatewaySecretRequired
	}
	return GatewayAuthenticator{secret: []byte(secret)}, nil
}

// Verify checks the base64url HMAC-SHA-256 signature over parts joined by |.
func (authenticator GatewayAuthenticator) Verify(parts []string, signature string) error {
	if len(authenticator.secret) == 0 {
		return ErrGatewaySecretRequired
	}
	mac := hmac.New(sha256.New, authenticator.secret)
	_, _ = mac.Write([]byte(strings.Join(parts, "|")))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrGatewaySignatureInvalid
	}
	return nil
}

// PeerApproval is the normalized service authorization supplied by VPN Server.
// It contains only public identity and assigned tunnel addresses.
type PeerApproval struct {
	PeerID    uint64
	UserID    string
	PublicKey [32]byte
	IPv4      [4]byte
	HasIPv4   bool
	IPv6      [16]byte
	HasIPv6   bool
	ExpiresAt time.Time
	ServerID  string
	DeviceID  string
}

// Validate checks service authorization before it crosses into Core state.
func (approval PeerApproval) Validate(now time.Time, expectedServerID string) error {
	if approval.PeerID == 0 || strings.TrimSpace(approval.UserID) == "" || len(approval.UserID) > 256 {
		return ErrApprovalInvalid
	}
	if approval.ServerID == "" || approval.DeviceID == "" {
		return ErrApprovalInvalid
	}
	if expectedServerID != "" && approval.ServerID != expectedServerID {
		return ErrApprovalServerMismatch
	}
	if approval.ExpiresAt.IsZero() || !approval.ExpiresAt.After(now) {
		return ErrApprovalInvalid
	}
	if isZeroKey(approval.PublicKey) {
		return ErrApprovalInvalid
	}
	if !validTunnelAddress(approval.IPv4, approval.HasIPv4, approval.IPv6, approval.HasIPv6) {
		return ErrApprovalInvalid
	}
	return nil
}

// ProtocolPeer converts a validated approval to the Core IPC type.
func (approval PeerApproval) ProtocolPeer(now time.Time, expectedServerID string) (protocol.PeerRegistration, error) {
	if err := approval.Validate(now, expectedServerID); err != nil {
		return protocol.PeerRegistration{}, err
	}
	return protocol.PeerRegistration{
		PeerID: approval.PeerID, UserID: approval.UserID, PublicKey: approval.PublicKey,
		IPv4: approval.IPv4, HasIPv4: approval.HasIPv4,
		IPv6: approval.IPv6, HasIPv6: approval.HasIPv6,
		ExpiresAt: approval.ExpiresAt,
	}, nil
}

// VPNServerAuthorization is the Controller boundary for normalized VPN
// Server approvals and does not know Gateway login or account APIs.
type VPNServerAuthorization struct {
	Controller       *CoreController
	Authenticator    GatewayAuthenticator
	ExpectedServerID string
	Now              func() time.Time
}

// Approve verifies the service signature, validates the grant, and applies it
// to desired state and the running Core.
func (authorization VPNServerAuthorization) Approve(ctx context.Context, parts []string, signature string, approval PeerApproval, requestID uint64) error {
	if authorization.Controller == nil {
		return fmt.Errorf("%w: controller is required", ErrApprovalInvalid)
	}
	if err := authorization.Authenticator.Verify(parts, signature); err != nil {
		return err
	}
	now := time.Now()
	if authorization.Now != nil {
		now = authorization.Now()
	}
	peer, err := approval.ProtocolPeer(now, authorization.ExpectedServerID)
	if err != nil {
		return err
	}
	return authorization.Controller.ApplyPeerApproval(ctx, peer, requestID)
}

// Revoke verifies the service signature and removes an approval from desired
// state and Core.
func (authorization VPNServerAuthorization) Revoke(ctx context.Context, parts []string, signature string, peerID, requestID uint64) error {
	if authorization.Controller == nil {
		return fmt.Errorf("%w: controller is required", ErrApprovalInvalid)
	}
	if err := authorization.Authenticator.Verify(parts, signature); err != nil {
		return err
	}
	return authorization.Controller.RevokePeerApproval(ctx, peerID, requestID)
}

// CreateSession creates a Core session only for a currently desired-approved
// peer. Core repeats the authorization check at the data-plane boundary.
func (authorization VPNServerAuthorization) CreateSession(ctx context.Context, peerID uint64, sessionID uint32, requestID uint64) (protocol.SessionStatus, error) {
	if authorization.Controller == nil {
		return protocol.SessionStatus{}, fmt.Errorf("%w: controller is required", ErrApprovalInvalid)
	}
	if err := ctx.Err(); err != nil {
		return protocol.SessionStatus{}, err
	}
	if _, ok := authorization.Controller.DesiredState().peers[peerID]; !ok {
		return protocol.SessionStatus{}, ErrPeerNotApproved
	}
	status := authorization.Controller.Status()
	if status.State != CoreRunning {
		return protocol.SessionStatus{}, ErrCoreNotStarted
	}
	authorization.Controller.mu.Lock()
	socketPath := authorization.Controller.config.SocketPath
	authorization.Controller.mu.Unlock()
	return (Client{SocketPath: socketPath}).CreateSession(requestID, protocol.SessionRequest{SessionID: sessionID, PeerID: peerID})
}

func isZeroKey(key [32]byte) bool {
	var zero [32]byte
	return key == zero
}

func validTunnelAddress(ipv4 [4]byte, hasIPv4 bool, ipv6 [16]byte, hasIPv6 bool) bool {
	if !hasIPv4 && !hasIPv6 {
		return false
	}
	if hasIPv4 {
		address := net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		network := &net.IPNet{IP: net.IPv4(10, 80, 0, 0), Mask: net.CIDRMask(16, 32)}
		if !network.Contains(address) || address.Equal(net.IPv4(10, 80, 0, 1)) {
			return false
		}
	}
	if hasIPv6 {
		address := net.IP(ipv6[:])
		network := &net.IPNet{IP: net.ParseIP("fd80:1234:5678::"), Mask: net.CIDRMask(64, 128)}
		if !network.Contains(address) || address.Equal(net.ParseIP("fd80:1234:5678::1")) {
			return false
		}
	}
	return true
}
