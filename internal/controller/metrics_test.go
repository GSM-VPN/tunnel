package controller

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

func TestCoreControllerCollectsHealthAndMetricsSnapshot(t *testing.T) {
	socketPath := "/tmp/tunnel-metrics-test.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
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
			payload := []byte("running")
			if request.Operation == protocol.OperationGetMetrics {
				payload = make([]byte, 11*8)
				binary.BigEndian.PutUint64(payload[0:8], 2)
				binary.BigEndian.PutUint64(payload[8:16], 100)
				binary.BigEndian.PutUint64(payload[16:24], 80)
			}
			response, marshalErr := (protocol.ManagementResponse{
				Version: request.Version, RequestID: request.RequestID, Status: 200,
				Payload: payload,
			}).MarshalFrame()
			if marshalErr == nil {
				_, _ = connection.Write(response)
			}
			connection.Close()
		}
	}()

	process := &fakeProcess{result: make(chan error)}
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: socketPath},
		DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return process, nil },
	)
	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForState(t, controller, CoreRunning)

	snapshot, err := controller.CollectMetrics(context.Background(), 41)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Health != "running" || snapshot.Metrics.ActiveSessions != 2 || snapshot.Metrics.TxBytes != 100 || snapshot.Metrics.RxBytes != 80 {
		t.Fatalf("unexpected Core snapshot: %+v", snapshot)
	}
	if err := controller.Stop(); err != nil {
		t.Fatal(err)
	}
	<-serverDone
}

func TestCoreControllerRejectsMetricsWhenNotRunning(t *testing.T) {
	controller := newCoreController(
		CoreCommand{SocketPath: "/tmp/core.sock"},
		DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return nil, nil },
	)
	if _, err := controller.CollectMetrics(context.Background(), 1); err != ErrCoreMetricsUnavailable {
		t.Fatalf("unexpected metrics error: %v", err)
	}
	if _, err := controller.CollectMetrics(context.Background(), ^uint64(0)); err != ErrCoreMetricsUnavailable {
		t.Fatalf("unexpected request ID error: %v", err)
	}
	if _, err := controller.CollectMetrics(context.Background(), 1); err != ErrCoreMetricsUnavailable {
		t.Fatalf("unexpected stopped-state error: %v", err)
	}
}
