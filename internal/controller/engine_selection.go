package controller

import "fmt"

// EngineKind identifies a tunnel implementation without coupling the
// controller to a WireGuard process or the Rust Core implementation.
type EngineKind string

const (
	EngineWireGuard  EngineKind = "wireguard"
	EngineTunnelCore EngineKind = "tunnel-core"
)

// EngineSelection is an explicit, deployment-owned engine policy.
//
// Fallback never happens implicitly. When Auto is selected, the controller
// reports that a WireGuard fallback is available, but an operator or service
// policy must approve the transition before traffic is moved.
type EngineSelection struct {
	Primary               EngineKind
	Fallback              EngineKind
	FallbackNeedsApproval bool
}

// ParseEngineSelection parses TUNNEL_ENGINE values.
//
// Supported values are `wireguard`, `tunnel-core`, and `auto`. Auto prefers
// Tunnel Core and preserves WireGuard as a manually approved fallback.
func ParseEngineSelection(value string) (EngineSelection, error) {
	switch value {
	case string(EngineWireGuard):
		return EngineSelection{Primary: EngineWireGuard}, nil
	case string(EngineTunnelCore):
		return EngineSelection{Primary: EngineTunnelCore}, nil
	case "auto":
		return EngineSelection{
			Primary:               EngineTunnelCore,
			Fallback:              EngineWireGuard,
			FallbackNeedsApproval: true,
		}, nil
	default:
		return EngineSelection{}, fmt.Errorf("unsupported tunnel engine %q", value)
	}
}

// FallbackAllowed reports whether a failed primary may be replaced.
//
// This method is deliberately pure: starting another engine and moving
// routes remain responsibilities of the deployment adapter.
func (selection EngineSelection) FallbackAllowed(operatorApproved bool) bool {
	return selection.Fallback != "" && (!selection.FallbackNeedsApproval || operatorApproved)
}
