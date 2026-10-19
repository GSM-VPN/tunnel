package controller

import (
	"errors"
	"testing"
)

func TestParseVPNServerConfigPreservesExistingEnvironmentContract(t *testing.T) {
	values := map[string]string{
		GatewaySharedSecretEnv: "gateway-secret",
		VPNServerIDEnv:         "server-a",
		TunnelCoreBinaryEnv:    "/usr/local/bin/tunnel-core",
		TunnelCoreSocketEnv:    "/run/gsm-tunnel/core.sock",
		TunnelCoreMaxPeersEnv:  "216",
	}
	config, err := ParseVPNServerConfig(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.gatewaySharedSecret != "gateway-secret" || config.ExpectedServerID != "server-a" {
		t.Fatalf("unexpected service configuration: %+v", config)
	}
	if config.Core.BinaryPath != values[TunnelCoreBinaryEnv] || config.Core.SocketPath != values[TunnelCoreSocketEnv] {
		t.Fatalf("unexpected core command: %+v", config.Core)
	}
	if config.Core.MaxPeers != 216 {
		t.Fatalf("unexpected peer limit: %d", config.Core.MaxPeers)
	}
	authenticator, err := config.Authenticator()
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify([]string{"server-a", "peer-1"}, "invalid"); !errors.Is(err, ErrGatewaySignatureInvalid) {
		t.Fatalf("unexpected authenticator result: %v", err)
	}
}

func TestParseVPNServerConfigAppliesSafePeerDefault(t *testing.T) {
	values := map[string]string{
		GatewaySharedSecretEnv: "secret",
		TunnelCoreBinaryEnv:    "tunnel-core",
		TunnelCoreSocketEnv:    "/tmp/core.sock",
	}
	config, err := ParseVPNServerConfig(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Core.MaxPeers != 216 {
		t.Fatalf("expected 216 peer default, got %d", config.Core.MaxPeers)
	}
}

func TestParseVPNServerConfigRejectsMissingSecretAndUnsafePeerLimit(t *testing.T) {
	values := map[string]string{
		TunnelCoreBinaryEnv:   "tunnel-core",
		TunnelCoreSocketEnv:   "/tmp/core.sock",
		TunnelCoreMaxPeersEnv: "217",
	}
	if _, err := ParseVPNServerConfig(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}); !errors.Is(err, ErrVPNServerSecretMissing) {
		t.Fatalf("unexpected missing secret error: %v", err)
	}
	values[GatewaySharedSecretEnv] = "secret"
	if _, err := ParseVPNServerConfig(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}); !errors.Is(err, ErrVPNServerMaxPeersInvalid) {
		t.Fatalf("unexpected peer limit error: %v", err)
	}
}
