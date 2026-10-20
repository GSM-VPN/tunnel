package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

func TestGatewayAuthenticatorMatchesVpnServerSignatureFormat(t *testing.T) {
	parts := []string{"POST", "/peers", "device-7", "1700000000"}
	authenticator, err := NewGatewayAuthenticator("shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("shared-secret"))
	_, _ = mac.Write([]byte("POST|/peers|device-7|1700000000"))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if err := authenticator.Verify(parts, signature); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify(parts, signature+"x"); !errors.Is(err, ErrGatewaySignatureInvalid) {
		t.Fatalf("unexpected invalid signature error: %v", err)
	}
	if _, err := NewGatewayAuthenticator(" "); !errors.Is(err, ErrGatewaySecretRequired) {
		t.Fatalf("unexpected empty secret error: %v", err)
	}
}

func TestPeerApprovalValidatesServerIdentityAndTunnelAddresses(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	approval := validApproval(now)
	if err := approval.Validate(now, "server-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := approval.ProtocolPeer(now, "server-1"); err != nil {
		t.Fatal(err)
	}
	approval.ServerID = "server-2"
	if !errors.Is(approval.Validate(now, "server-1"), ErrApprovalServerMismatch) {
		t.Fatal("server mismatch was accepted")
	}
	approval = validApproval(now)
	approval.IPv4 = [4]byte{192, 168, 1, 2}
	if !errors.Is(approval.Validate(now, "server-1"), ErrApprovalInvalid) {
		t.Fatal("out-of-range IPv4 address was accepted")
	}
	approval = validApproval(now)
	approval.ExpiresAt = now
	if !errors.Is(approval.Validate(now, "server-1"), ErrApprovalInvalid) {
		t.Fatal("expired approval was accepted")
	}
}

func TestAuthorizationApprovalUpdatesDesiredStateWithoutExposingSecrets(t *testing.T) {
	controller := newCoreController(
		CoreCommand{SocketPath: "/tmp/core.sock"}, DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return nil, nil },
	)
	authenticator, err := NewGatewayAuthenticator("shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	service := VPNServerAuthorization{
		Controller: controller, Authenticator: authenticator,
		ExpectedServerID: "server-1", Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	parts := []string{"POST", "/peers", "device-7", "1700000000"}
	signature := signGatewayParts("shared-secret", parts)
	approval := validApproval(time.Unix(1_700_000_000, 0))
	if err := service.Approve(context.Background(), parts, signature, approval, 1); err != nil {
		t.Fatal(err)
	}
	state := controller.DesiredState()
	peer, ok := state.peers[approval.PeerID]
	if !ok || peer.UserID != approval.UserID || peer.PublicKey != approval.PublicKey {
		t.Fatalf("approval was not stored: %+v", state)
	}
	if _, err := service.CreateSession(context.Background(), approval.PeerID, 1, 2); !errors.Is(err, ErrCoreNotStarted) {
		t.Fatalf("unexpected session error: %v", err)
	}
	if err := service.Revoke(context.Background(), parts, signature, approval.PeerID, 3); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.DesiredState().peers[approval.PeerID]; ok {
		t.Fatal("revoked approval remains in desired state")
	}
	if err := service.Approve(context.Background(), parts, signature, approval, 4); err != nil {
		t.Fatal(err)
	}
	if err := service.PurgeKey(context.Background(), parts, signature, approval.PeerID, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateSession(context.Background(), approval.PeerID, 2, 6); !errors.Is(err, ErrPeerNotApproved) {
		t.Fatalf("purged key remained connectable: %v", err)
	}
}

func TestAuthorizationReceivesGatewayApprovalResultAsOneBoundary(t *testing.T) {
	controller := newCoreController(
		CoreCommand{SocketPath: "/tmp/core.sock"}, DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return nil, nil },
	)
	authenticator, err := NewGatewayAuthenticator("shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	service := VPNServerAuthorization{
		Controller: controller, Authenticator: authenticator,
		ExpectedServerID: "server-1", Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	parts := []string{"POST", "/peers", "device-7", "1700000000"}
	result := GatewayApprovalResult{
		SignatureParts: parts,
		Signature:      signGatewayParts("shared-secret", parts),
		Approval:       validApproval(time.Unix(1_700_000_000, 0)),
		RequestID:      11,
	}
	if err := service.ReceiveApproval(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.DesiredState().peers[result.Approval.PeerID]; !ok {
		t.Fatal("Gateway approval result was not applied")
	}

	result.Signature = result.Signature + "tampered"
	result.Approval.PeerID++
	if err := service.ReceiveApproval(context.Background(), result); !errors.Is(err, ErrGatewaySignatureInvalid) {
		t.Fatalf("unexpected tampered approval result: %v", err)
	}
	if _, ok := controller.DesiredState().peers[result.Approval.PeerID]; ok {
		t.Fatal("tampered Gateway approval changed desired state")
	}
}

func TestConnectionStatusRequiresAnApprovedPeerAndRunningCore(t *testing.T) {
	controller := newCoreController(
		CoreCommand{SocketPath: "/tmp/core.sock"}, DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return nil, nil },
	)
	service := VPNServerAuthorization{Controller: controller}
	if _, err := service.ConnectionStatus(context.Background(), 7, 1, 1); !errors.Is(err, ErrPeerNotApproved) {
		t.Fatalf("unexpected unapproved status error: %v", err)
	}
	controller.ApprovePeer(protocol.PeerRegistration{PeerID: 7, UserID: "user-7"})
	if _, err := service.ConnectionStatus(context.Background(), 7, 1, 1); !errors.Is(err, ErrCoreNotStarted) {
		t.Fatalf("unexpected stopped-core status error: %v", err)
	}
}

func validApproval(now time.Time) PeerApproval {
	return PeerApproval{
		PeerID: 7, UserID: "user-7", PublicKey: [32]byte{9},
		IPv4: [4]byte{10, 80, 0, 2}, HasIPv4: true,
		ExpiresAt: now.Add(time.Hour), ServerID: "server-1", DeviceID: "device-7",
	}
}

func signGatewayParts(secret string, parts []string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	for index, part := range parts {
		if index > 0 {
			_, _ = mac.Write([]byte("|"))
		}
		_, _ = mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
