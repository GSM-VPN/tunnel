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
