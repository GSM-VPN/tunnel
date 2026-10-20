package controller

import "testing"

func TestEngineSelectionPreservesWireGuardFallbackUntilApproved(t *testing.T) {
	selection, err := ParseEngineSelection("auto")
	if err != nil {
		t.Fatal(err)
	}
	if selection.Primary != EngineTunnelCore || selection.Fallback != EngineWireGuard {
		t.Fatalf("unexpected selection: %+v", selection)
	}
	if selection.FallbackAllowed(false) {
		t.Fatal("auto mode switched without explicit approval")
	}
	if !selection.FallbackAllowed(true) {
		t.Fatal("approved WireGuard fallback was not available")
	}
}

func TestEngineSelectionRejectsUnknownValues(t *testing.T) {
	if _, err := ParseEngineSelection("openvpn"); err == nil {
		t.Fatal("unknown engine was accepted")
	}
	wireguard, err := ParseEngineSelection("wireguard")
	if err != nil || wireguard.FallbackAllowed(true) {
		t.Fatalf("WireGuard-only selection has an unexpected fallback: %+v, %v", wireguard, err)
	}
}
