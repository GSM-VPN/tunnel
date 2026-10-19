package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

func TestCoreControllerRestartsAndReportsUnhealthy(t *testing.T) {
	var starts atomic.Uint32
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: "/tmp/core.sock"},
		RestartPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
		func(context.Context, CoreCommand) (CoreProcess, error) {
			starts.Add(1)
			process := &fakeProcess{result: make(chan error, 1)}
			process.result <- errors.New("core crashed")
			return process, nil
		},
	)
	if err := controller.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := controller.Wait(context.Background()); !errors.Is(err, ErrCoreUnhealthy) {
		t.Fatalf("unexpected wait result: %v", err)
	}
	status := controller.Status()
	if status.State != CoreUnhealthy || status.StartCount != 3 || starts.Load() != 3 {
		t.Fatalf("unexpected status: %+v starts=%d", status, starts.Load())
	}
	if status.LastError == "" {
		t.Fatal("unhealthy status did not expose a reason")
	}
}

func TestCoreControllerSynchronizesDesiredStateBeforeRunning(t *testing.T) {
	process := &fakeProcess{result: make(chan error)}
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: "/tmp/core.sock"},
		DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) { return process, nil },
	)
	controller.ApprovePeer(protocol.PeerRegistration{PeerID: 7, UserID: "user"})
	var synchronized atomic.Bool
	controller.synchronize = func(_ context.Context, desired CoreDesiredState) error {
		synchronized.Store(true)
		if _, ok := desired.peers[7]; !ok {
			t.Fatal("approved peer was not included in desired state")
		}
		return nil
	}

	if err := controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForState(t, controller, CoreRunning)
	if !synchronized.Load() {
		t.Fatal("Core entered running state without synchronization")
	}
	if err := controller.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestCoreControllerStopCleansUpRunningProcess(t *testing.T) {
	process := &fakeProcess{result: make(chan error)}
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: "/tmp/core.sock"},
		DefaultRestartPolicy(),
		func(context.Context, CoreCommand) (CoreProcess, error) {
			return process, nil
		},
	)
	if err := controller.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	waitForState(t, controller, CoreRunning)
	if err := controller.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if !process.stopped.Load() {
		t.Fatal("running Core process was not stopped")
	}
	if status := controller.Status(); status.State != CoreStopped {
		t.Fatalf("unexpected stopped status: %+v", status)
	}
}

func TestCoreControllerRejectsDuplicateStartAndSupportsRestartAfterFailure(t *testing.T) {
	var starts atomic.Uint32
	controller := newCoreController(
		CoreCommand{BinaryPath: "core", SocketPath: "/tmp/core.sock"},
		RestartPolicy{MaxAttempts: 1},
		func(context.Context, CoreCommand) (CoreProcess, error) {
			starts.Add(1)
			return nil, errors.New("cannot start")
		},
	)
	if err := controller.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := controller.Start(context.Background()); !errors.Is(err, ErrCoreAlreadyStarted) {
		t.Fatalf("unexpected duplicate start result: %v", err)
	}
	_ = controller.Wait(context.Background())
	if err := controller.Start(context.Background()); err != nil {
		t.Fatalf("restart after failure failed: %v", err)
	}
	_ = controller.Wait(context.Background())
	if starts.Load() != 2 {
		t.Fatalf("expected two start attempts, got %d", starts.Load())
	}
}

func waitForState(t *testing.T, controller *CoreController, expected CoreState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if controller.Status().State == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state did not become %v: %+v", expected, controller.Status())
}
