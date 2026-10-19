package controller

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

func TestClientCallsUnixSocketAndMatchesRequestID(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/tunnel-ipc-%d.sock", os.Getpid())
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		requestFrame, readErr := readFrame(connection)
		if readErr != nil {
			return
		}
		request, decodeErr := protocol.UnmarshalRequestFrame(requestFrame)
		if decodeErr != nil {
			return
		}
		response, marshalErr := (protocol.ManagementResponse{
			Version: request.Version, RequestID: request.RequestID, Status: 200, Payload: []byte("healthy"),
		}).MarshalFrame()
		if marshalErr == nil {
			_, _ = connection.Write(response)
		}
	}()

	response, err := (Client{SocketPath: socketPath, Timeout: time.Second}).Call(protocol.ManagementRequest{
		Version: protocol.ManagementVersion, RequestID: 7, Operation: protocol.OperationHealth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != 200 || string(response.Payload) != "healthy" {
		t.Fatalf("unexpected response: %+v", response)
	}
}
