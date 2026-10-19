package controller

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// Existing vpn-server service authentication variable.
	GatewaySharedSecretEnv = "GATEWAY_SHARED_SECRET"
	// Optional deployment identity used to bind approvals to one server.
	VPNServerIDEnv = "VPN_SERVER_ID"
	// Tunnel process settings consumed by the Go Controller.
	TunnelCoreBinaryEnv   = "TUNNEL_CORE_BINARY"
	TunnelCoreSocketEnv   = "TUNNEL_CORE_IPC_SOCKET"
	TunnelCoreMaxPeersEnv = "TUNNEL_CORE_MAX_PEERS"
)

var (
	ErrVPNServerSecretMissing     = errors.New("vpn-server gateway secret is missing")
	ErrVPNServerCoreBinaryMissing = errors.New("tunnel core binary is missing")
	ErrVPNServerSocketMissing     = errors.New("tunnel core socket is missing")
	ErrVPNServerMaxPeersInvalid   = errors.New("tunnel core max peers is invalid")
)

// VPNServerConfig is the deployment boundary for existing vpn-server settings.
// The gateway secret is retained only long enough to construct the Go-side HMAC
// authenticator and is never added to CoreCommand.Env.
type VPNServerConfig struct {
	gatewaySharedSecret string
	ExpectedServerID    string
	Core                CoreCommand
}

// LoadVPNServerConfig reads the established environment names using the
// process environment.
func LoadVPNServerConfig() (VPNServerConfig, error) {
	return ParseVPNServerConfig(lookupEnvironment)
}

// ParseVPNServerConfig makes environment loading testable without mutating the
// process environment.
func ParseVPNServerConfig(lookup func(string) (string, bool)) (VPNServerConfig, error) {
	secret, ok := lookup(GatewaySharedSecretEnv)
	if !ok || strings.TrimSpace(secret) == "" {
		return VPNServerConfig{}, ErrVPNServerSecretMissing
	}
	binaryPath, ok := lookup(TunnelCoreBinaryEnv)
	if !ok || strings.TrimSpace(binaryPath) == "" {
		return VPNServerConfig{}, ErrVPNServerCoreBinaryMissing
	}
	socketPath, ok := lookup(TunnelCoreSocketEnv)
	if !ok || strings.TrimSpace(socketPath) == "" {
		return VPNServerConfig{}, ErrVPNServerSocketMissing
	}
	maxPeers, err := parseMaxPeers(lookup)
	if err != nil {
		return VPNServerConfig{}, err
	}
	serverID, _ := lookup(VPNServerIDEnv)
	return VPNServerConfig{
		gatewaySharedSecret: secret,
		ExpectedServerID:    serverID,
		Core: CoreCommand{
			BinaryPath: binaryPath,
			SocketPath: socketPath,
			MaxPeers:   maxPeers,
		},
	}, nil
}

// Authenticator constructs the service-plane verifier without exposing the
// secret to the Rust process or an IPC payload.
func (config VPNServerConfig) Authenticator() (GatewayAuthenticator, error) {
	return NewGatewayAuthenticator(config.gatewaySharedSecret)
}

func lookupEnvironment(name string) (string, bool) {
	return os.LookupEnv(name)
}

func parseMaxPeers(lookup func(string) (string, bool)) (uint32, error) {
	value, ok := lookup(TunnelCoreMaxPeersEnv)
	if !ok || strings.TrimSpace(value) == "" {
		return 216, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 || parsed > 216 {
		return 0, fmt.Errorf("%w: %q", ErrVPNServerMaxPeersInvalid, value)
	}
	return uint32(parsed), nil
}
