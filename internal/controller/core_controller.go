package controller

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrCoreAlreadyStarted = errors.New("tunnel core controller is already started")
	ErrCoreNotStarted     = errors.New("tunnel core controller is not started")
)

// CoreState is the controller-owned lifecycle state of the Rust Core child.
type CoreState uint8

const (
	CoreStopped CoreState = iota
	CoreStarting
	CoreRunning
	CoreStopping
	CoreUnhealthy
)

// CoreStatus is a secret-free snapshot suitable for operational reporting.
type CoreStatus struct {
	State      CoreState
	StartCount uint32
	LastError  string
}

type coreStarter func(context.Context, CoreCommand) (CoreProcess, error)

// CoreController connects the Core process, bounded supervisor, and exposed
// lifecycle state into one controller-owned boundary.
type CoreController struct {
	mu         sync.Mutex
	config     CoreCommand
	supervisor Supervisor
	start      coreStarter
	state      CoreState
	startCount uint32
	lastError  error
	cancel     context.CancelFunc
	done       chan struct{}
	result     error
}

// NewCoreController creates a controller that launches the configured Rust
// Core binary.
func NewCoreController(config CoreCommand, policy RestartPolicy) *CoreController {
	if policy.MaxAttempts == 0 {
		policy = DefaultRestartPolicy()
	}
	return newCoreController(config, policy, func(ctx context.Context, config CoreCommand) (CoreProcess, error) {
		return StartCore(ctx, config)
	})
}

func newCoreController(config CoreCommand, policy RestartPolicy, start coreStarter) *CoreController {
	return &CoreController{
		config:     config,
		supervisor: Supervisor{Policy: policy},
		start:      start,
		state:      CoreStopped,
	}
}

// Start begins Core supervision and returns once the monitor is installed.
func (controller *CoreController) Start(ctx context.Context) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.state != CoreStopped && controller.state != CoreUnhealthy {
		return ErrCoreAlreadyStarted
	}
	runContext, cancel := context.WithCancel(ctx)
	controller.cancel = cancel
	controller.done = make(chan struct{})
	controller.result = nil
	controller.lastError = nil
	controller.state = CoreStarting
	go controller.run(runContext)
	return nil
}

// Stop cancels supervision and waits for the child process to be collected.
func (controller *CoreController) Stop() error {
	controller.mu.Lock()
	if controller.state == CoreStopped {
		controller.mu.Unlock()
		return nil
	}
	if controller.state == CoreUnhealthy {
		controller.state = CoreStopped
		controller.mu.Unlock()
		return nil
	}
	if controller.cancel == nil || controller.done == nil {
		controller.mu.Unlock()
		return ErrCoreNotStarted
	}
	controller.state = CoreStopping
	cancel := controller.cancel
	done := controller.done
	controller.mu.Unlock()
	cancel()
	<-done
	return nil
}

// Wait waits for supervision to finish and returns its terminal result.
func (controller *CoreController) Wait(ctx context.Context) error {
	controller.mu.Lock()
	if controller.done == nil {
		controller.mu.Unlock()
		return ErrCoreNotStarted
	}
	done := controller.done
	controller.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return controller.result
	}
}

// Status returns a secret-free lifecycle snapshot.
func (controller *CoreController) Status() CoreStatus {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	status := CoreStatus{
		State:      controller.state,
		StartCount: controller.startCount,
	}
	if controller.lastError != nil {
		status.LastError = controller.lastError.Error()
	}
	return status
}

func (controller *CoreController) run(ctx context.Context) {
	result := controller.supervisor.Run(ctx, func() (CoreProcess, error) {
		process, err := controller.start(ctx, controller.config)
		if err != nil {
			return nil, err
		}
		controller.mu.Lock()
		controller.startCount++
		controller.state = CoreRunning
		controller.mu.Unlock()
		return process, nil
	})

	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.result = result
	if controller.state == CoreStopping || errors.Is(result, context.Canceled) {
		controller.state = CoreStopped
		controller.result = nil
	} else if result != nil {
		controller.state = CoreUnhealthy
		controller.lastError = result
	} else {
		controller.state = CoreStopped
	}
	close(controller.done)
}
