package protocol

import (
	"reflect"
	"testing"
	"time"
)

func TestManagementMessagesDoNotExposeKeyFields(t *testing.T) {
	typeName := reflect.TypeOf(ManagementRequest{}).String()
	if typeName != "protocol.ManagementRequest" {
		t.Fatalf("unexpected request type: %s", typeName)
	}
	for _, fieldName := range []string{"Key", "Secret", "PrivateKey", "PublicKey"} {
		if _, ok := reflect.TypeOf(ManagementRequest{}).FieldByName(fieldName); ok {
			t.Fatalf("management request exposes forbidden field %q", fieldName)
		}
	}
}

func TestManagementRequestCarriesControlMetadata(t *testing.T) {
	request := ManagementRequest{
		Version:   ManagementVersion,
		RequestID: 9,
		Operation: OperationHealth,
		Payload:   []byte("status"),
	}
	if request.Version != ManagementVersion || request.RequestID != 9 || request.Operation != OperationHealth {
		t.Fatalf("unexpected management request: %+v", request)
	}
}

func TestManagementOperationsAreStableAndValidated(t *testing.T) {
	if OperationInitialize != 1 || OperationHealth != 12 {
		t.Fatalf("unexpected operation contract: initialize=%d health=%d", OperationInitialize, OperationHealth)
	}
	if !OperationRegisterPeer.IsValid() || Operation(99).IsValid() {
		t.Fatal("operation validation contract is incorrect")
	}
	request := ManagementRequest{Version: ManagementVersion, RequestID: 1, Operation: Operation(99)}
	if _, err := request.MarshalFrame(); err != ErrUnknownOperation {
		t.Fatalf("expected unknown operation error, got %v", err)
	}
}

func TestManagementResponsePayloadIsOpaque(t *testing.T) {
	response := ManagementResponse{Version: ManagementVersion, RequestID: 9, Status: 200, Payload: []byte{1, 2}}
	if !reflect.DeepEqual(response.Payload, []byte{1, 2}) {
		t.Fatalf("unexpected response payload: %v", response.Payload)
	}
}

func TestManagementRequestRoundTripsLengthPrefixedFrame(t *testing.T) {
	want := ManagementRequest{Version: ManagementVersion, RequestID: 42, Operation: OperationStart, Payload: []byte("config")}
	frame, err := want.MarshalFrame()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalRequestFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request mismatch: got %+v want %+v", got, want)
	}
}

func TestManagementResponseRoundTripsLengthPrefixedFrame(t *testing.T) {
	want := ManagementResponse{Version: ManagementVersion, RequestID: 42, Status: 200, ErrorCode: 0, Payload: []byte("ok")}
	frame, err := want.MarshalFrame()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalResponseFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response mismatch: got %+v want %+v", got, want)
	}
}

func TestSessionPayloadAndStatusRoundTrip(t *testing.T) {
	request := SessionRequest{SessionID: 9, PeerID: 7}
	status, err := UnmarshalSessionStatus(append(request.MarshalBinary(), 3))
	if err != nil {
		t.Fatal(err)
	}
	if status != (SessionStatus{SessionID: 9, PeerID: 7, State: 3}) {
		t.Fatalf("unexpected session status: %+v", status)
	}
}

func TestNetworkConfigurationPayloadUsesStableLayout(t *testing.T) {
	payload := (NetworkConfiguration{UDPPort: 51820, MTU: 1400, DualStack: true}).MarshalBinary()
	want := []byte{16, 64, 0xca, 0x6c, 0x05, 0x78, 1, 0, 0, 0}
	if !reflect.DeepEqual(payload, want) {
		t.Fatalf("unexpected configuration payload: %v", payload)
	}
}

func TestManagementFrameRejectsTruncationAndOversize(t *testing.T) {
	request := ManagementRequest{Version: ManagementVersion, RequestID: 1, Operation: OperationHealth}
	frame, err := request.MarshalFrame()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRequestFrame(frame[:len(frame)-1]); err == nil {
		t.Fatal("expected truncated frame error")
	}
	request.Payload = make([]byte, MaxManagementFrameSize)
	if _, err := request.MarshalFrame(); err != ErrManagementFrameTooLarge {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestManagementFrameRejectsZeroVersionOnDecode(t *testing.T) {
	frame, err := (ManagementRequest{Version: ManagementVersion, RequestID: 1, Operation: OperationHealth}).MarshalFrame()
	if err != nil {
		t.Fatal(err)
	}
	frame[4] = 0
	frame[5] = 0
	if _, err := UnmarshalRequestFrame(frame); err == nil {
		t.Fatal("expected zero request version error")
	}
}

func TestPeerRegistrationPayloadRoundTripsStableLayout(t *testing.T) {
	peer := PeerRegistration{
		PeerID: 7, UserID: "user-7", PublicKey: [32]byte{3},
		IPv4: [4]byte{10, 80, 0, 2}, HasIPv4: true,
		ExpiresAt: time.Unix(1700000000, 0),
	}
	payload, err := MarshalPeerRegistration(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 77 || payload[40] != 1 {
		t.Fatalf("unexpected peer payload layout: len=%d flags=%d", len(payload), payload[40])
	}
	got, err := UnmarshalPeerRegistration(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, peer) {
		t.Fatalf("peer mismatch: got %+v want %+v", got, peer)
	}
}

func TestPeerRegistrationPayloadRejectsInvalidData(t *testing.T) {
	_, err := MarshalPeerRegistration(PeerRegistration{UserID: "user", ExpiresAt: time.Unix(1, 0)})
	if err != ErrPeerPayloadMalformed {
		t.Fatalf("expected malformed peer error, got %v", err)
	}
	_, err = UnmarshalPeerRegistration([]byte{1, 2})
	if err != ErrPeerPayloadMalformed {
		t.Fatalf("expected malformed payload error, got %v", err)
	}
}

func FuzzUnmarshalRequestFrameNeverPanics(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = UnmarshalRequestFrame(frame)
	})
}

func FuzzUnmarshalResponseFrameNeverPanics(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 22, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 200, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = UnmarshalResponseFrame(frame)
	})
}
