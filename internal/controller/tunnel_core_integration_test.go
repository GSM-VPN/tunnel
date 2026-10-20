//go:build integration

package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

// TestTunnelCoreBinaryManagementContract exercises the real Rust binary. It
// intentionally covers only the local management plane; privileged TUN,
// routing, and external Gateway integrations remain separate environments.
func TestTunnelCoreBinaryManagementContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Tunnel Core management IPC currently requires Unix Domain Sockets")
	}
	binaryPath := os.Getenv(TunnelCoreBinaryEnv)
	if binaryPath == "" {
		t.Skipf("set %s to run the Tunnel Core binary integration test", TunnelCoreBinaryEnv)
	}
	if _, err := os.Stat(binaryPath); err != nil {
		t.Fatalf("Tunnel Core binary is unavailable: %v", err)
	}

	// Unix socket addresses have a small platform-specific path limit. Keep
	// the integration path short enough for macOS and Linux alike.
	socketPath := fmt.Sprintf("/tmp/gsm-tunnel-core-it-%d.sock", os.Getpid())
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	coreConfig := CoreCommand{
		BinaryPath: binaryPath,
		SocketPath: socketPath,
		MaxPeers:   4,
		Env: []string{
			// Deterministic test identity; it is never sent over IPC.
			"SERVER_PRIVATE_KEY=" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	var process CoreProcess
	process, err := StartCore(context.Background(), coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if stopErr := process.Stop(); stopErr != nil && !errors.Is(stopErr, os.ErrProcessDone) {
			t.Errorf("stop Tunnel Core: %v", stopErr)
		}
		if waitErr := process.Wait(); waitErr != nil {
			t.Logf("Tunnel Core exited after test cleanup: %v", waitErr)
		}
	})

	client := Client{SocketPath: socketPath, Timeout: time.Second}
	waitForManagementSocket(t, socketPath)
	if _, err := client.Initialize(1); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateConfiguration(2, protocol.NetworkConfiguration{
		UDPPort: 51820, MTU: 1400, DualStack: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterPeer(3, protocol.PeerRegistration{
		PeerID: 7, UserID: "integration-user", PublicKey: [32]byte{7},
		IPv4: [4]byte{10, 80, 0, 2}, HasIPv4: true,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Start(4); err != nil {
		t.Fatal(err)
	}
	health, err := client.GetHealth(5)
	if err != nil {
		t.Fatal(err)
	}
	if health != "running" {
		t.Fatalf("unexpected Tunnel Core health: %q", health)
	}

	if err := process.Stop(); err != nil {
		t.Fatalf("stop Tunnel Core for restart: %v", err)
	}
	if err := process.Wait(); err != nil {
		t.Logf("Tunnel Core stopped for restart: %v", err)
	}
	process = nil
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove stale Tunnel Core management socket: %v", err)
	}

	process, err = StartCore(context.Background(), coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	waitForManagementSocket(t, socketPath)

	restartedClient := Client{SocketPath: socketPath, Timeout: time.Second}
	if _, err := restartedClient.Initialize(6); err != nil {
		t.Fatalf("initialize restarted Tunnel Core: %v", err)
	}
	if _, err := restartedClient.Start(7); err != nil {
		t.Fatalf("start restarted Tunnel Core: %v", err)
	}
	restartedHealth, err := restartedClient.GetHealth(8)
	if err != nil {
		t.Fatalf("read restarted Tunnel Core health: %v", err)
	}
	if restartedHealth != "running" {
		t.Fatalf("unexpected restarted Tunnel Core health: %q", restartedHealth)
	}
}

func waitForManagementSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Tunnel Core did not create management socket: %s", path)
}
