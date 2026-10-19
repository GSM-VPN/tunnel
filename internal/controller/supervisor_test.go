package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeProcess struct {
	result  chan error
	stopped atomic.Bool
}

func (process *fakeProcess) Wait() error { return <-process.result }
func (process *fakeProcess) Stop() error {
	process.stopped.Store(true)
	close(process.result)
	return nil
}

func TestSupervisorStopsAfterBoundedFailures(t *testing.T) {
	var starts atomic.Uint32
	supervisor := Supervisor{Policy: RestartPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}}
	err := supervisor.Run(context.Background(), func() (CoreProcess, error) {
		starts.Add(1)
		process := &fakeProcess{result: make(chan error, 1)}
		process.result <- errors.New("crash")
		return process, nil
	})
	if !errors.Is(err, ErrCoreUnhealthy) || starts.Load() != 3 {
		t.Fatalf("unexpected result: err=%v starts=%d", err, starts.Load())
	}
}

func TestSupervisorHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	process := &fakeProcess{result: make(chan error)}
	supervisor := Supervisor{Policy: DefaultRestartPolicy()}
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx, func() (CoreProcess, error) { return process, nil }) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !process.stopped.Load() {
			t.Fatalf("unexpected cancellation result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
	}
}

func TestRestartPolicyCapsExponentialDelay(t *testing.T) {
	policy := RestartPolicy{BaseDelay: time.Second, MaxDelay: 3 * time.Second}
	if policy.delay(1) != time.Second || policy.delay(2) != 2*time.Second || policy.delay(3) != 3*time.Second {
		t.Fatalf("unexpected delays: %s %s %s", policy.delay(1), policy.delay(2), policy.delay(3))
	}
}
