package protocol

import (
	"strings"
	"testing"
)

func TestPeerRegistrationStringRedactsUserID(t *testing.T) {
	peer := PeerRegistration{PeerID: 7, UserID: "sensitive-user"}
	text := peer.String()
	if !strings.Contains(text, "peer=7") {
		t.Fatalf("missing peer identifier: %q", text)
	}
	if strings.Contains(text, peer.UserID) {
		t.Fatalf("user ID was exposed: %q", text)
	}
}
