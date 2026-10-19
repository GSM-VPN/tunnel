package controller

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

func TestCoreDesiredStateCopiesApprovalsAndConfiguration(t *testing.T) {
	state := NewCoreDesiredState()
	configuration := protocol.NetworkConfiguration{UDPPort: 51820, MTU: 1400, DualStack: true}
	peer := testPeer(7)
	state.SetConfiguration(configuration)
	state.RegisterPeer(peer)

	snapshot := state.Snapshot()
	state.RemovePeer(peer.PeerID)
	state.SetConfiguration(protocol.NetworkConfiguration{UDPPort: 1})

	if !reflect.DeepEqual(snapshot.configuration, &configuration) {
		t.Fatalf("snapshot lost configuration: %+v", snapshot.configuration)
	}
	if got, ok := snapshot.peers[peer.PeerID]; !ok || !reflect.DeepEqual(got, peer) {
		t.Fatalf("snapshot lost peer: %+v", snapshot.peers)
	}
}

func TestCoreSynchronizerRestoresStateInDependencyOrder(t *testing.T) {
	socketPath := "/tmp/tunnel-reconcile-test.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	operations := make(chan protocol.Operation, 4)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for range 4 {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			frame, readErr := readFrame(connection)
			if readErr != nil {
				connection.Close()
				return
			}
			request, decodeErr := protocol.UnmarshalRequestFrame(frame)
			if decodeErr != nil {
				connection.Close()
				return
			}
			operations <- request.Operation
			response, marshalErr := (protocol.ManagementResponse{
				Version: request.Version, RequestID: request.RequestID, Status: 200,
			}).MarshalFrame()
			if marshalErr == nil {
				_, _ = connection.Write(response)
			}
			connection.Close()
		}
	}()

	state := NewCoreDesiredState()
	state.SetConfiguration(protocol.NetworkConfiguration{UDPPort: 51820, MTU: 1400, DualStack: true})
	state.RegisterPeer(testPeer(7))
	synchronizer := CoreSynchronizer{
		Client:       Client{SocketPath: socketPath, Timeout: time.Second},
		SocketWait:   time.Second,
		PollInterval: time.Millisecond,
	}
	if err := synchronizer.Synchronize(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	close(operations)
	<-serverDone
	var got []protocol.Operation
	for operation := range operations {
		got = append(got, operation)
	}
	want := []protocol.Operation{
		protocol.OperationInitialize,
		protocol.OperationUpdateConfiguration,
		protocol.OperationRegisterPeer,
		protocol.OperationStart,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected synchronization order: got %v want %v", got, want)
	}
}

func TestCoreSynchronizerStopsAtFailedOperation(t *testing.T) {
	socketPath := "/tmp/tunnel-reconcile-failure.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	operations := make(chan protocol.Operation, 2)
	go func() {
		for range 2 {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			frame, readErr := readFrame(connection)
			if readErr != nil {
				connection.Close()
				return
			}
			request, decodeErr := protocol.UnmarshalRequestFrame(frame)
			if decodeErr != nil {
				connection.Close()
				return
			}
			operations <- request.Operation
			status := uint16(200)
			if request.Operation == protocol.OperationRegisterPeer {
				status = 409
			}
			response, _ := (protocol.ManagementResponse{
				Version: request.Version, RequestID: request.RequestID, Status: status,
			}).MarshalFrame()
			_, _ = connection.Write(response)
			connection.Close()
		}
	}()

	state := NewCoreDesiredState()
	state.RegisterPeer(testPeer(7))
	err = (CoreSynchronizer{Client: Client{SocketPath: socketPath, Timeout: time.Second}}).Synchronize(context.Background(), state)
	if !errors.Is(err, ErrCoreSyncFailed) {
		t.Fatalf("expected synchronization failure, got %v", err)
	}
	if got := <-operations; got != protocol.OperationInitialize {
		t.Fatalf("first operation was %v", got)
	}
	if got := <-operations; got != protocol.OperationRegisterPeer {
		t.Fatalf("second operation was %v", got)
	}
}

func testPeer(id uint64) protocol.PeerRegistration {
	return protocol.PeerRegistration{
		PeerID: id, UserID: "user", PublicKey: [32]byte{1},
		IPv4: [4]byte{10, 80, 0, 2}, HasIPv4: true,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}
