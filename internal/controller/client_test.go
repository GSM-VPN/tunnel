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

func TestClientRegistersAndRemovesPeerOverIPC(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/tunnel-peer-ipc-%d.sock", os.Getpid())
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	requests := make(chan protocol.ManagementRequest, 2)
	go func() {
		for range 2 {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			requestFrame, readErr := readFrame(connection)
			if readErr != nil {
				connection.Close()
				return
			}
			request, decodeErr := protocol.UnmarshalRequestFrame(requestFrame)
			if decodeErr != nil {
				connection.Close()
				return
			}
			requests <- request
			response, marshalErr := (protocol.ManagementResponse{
				Version: request.Version, RequestID: request.RequestID, Status: 200,
			}).MarshalFrame()
			if marshalErr == nil {
				_, _ = connection.Write(response)
			}
			connection.Close()
		}
	}()

	client := Client{SocketPath: socketPath, Timeout: time.Second}
	_, err = client.RegisterPeer(8, protocol.PeerRegistration{
		PeerID: 7, UserID: "user-7", PublicKey: [32]byte{3},
		IPv4: [4]byte{10, 80, 0, 2}, HasIPv4: true,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.RemovePeer(9, 7); err != nil {
		t.Fatal(err)
	}
	close(requests)
	register := <-requests
	remove := <-requests
	if register.Operation != protocol.OperationRegisterPeer || remove.Operation != protocol.OperationRemovePeer {
		t.Fatalf("unexpected operations: %v, %v", register.Operation, remove.Operation)
	}
	peer, err := protocol.UnmarshalPeerRegistration(register.Payload)
	if err != nil || peer.PeerID != 7 {
		t.Fatalf("unexpected peer payload: %+v, %v", peer, err)
	}
	if len(remove.Payload) != 8 {
		t.Fatalf("unexpected remove payload length: %d", len(remove.Payload))
	}
}
