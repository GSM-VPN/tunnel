package protocol

import (
	"reflect"
	"testing"
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
