package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/GSM-VPN/tunnel/internal/protocol"
)

var (
	ErrCoreAlreadyStarted     = errors.New("tunnel core controller is already started")
	ErrCoreNotStarted         = errors.New("tunnel core controller is not started")
	ErrCoreMetricsUnavailable = errors.New("core metrics are unavailable")
	ErrCoreRequestIDExhausted = errors.New("core IPC request ID is exhausted")
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

// CoreMetricsSnapshot combines the Core health label and secret-free counters.
type CoreMetricsSnapshot struct {
	Health  string
	Metrics protocol.MetricsSnapshot
}

type coreStarter func(context.Context, CoreCommand) (CoreProcess, error)

// CoreController connects the Core process, bounded supervisor, and exposed
// lifecycle state into one controller-owned boundary.
type CoreController struct {
	mu          sync.Mutex
	config      CoreCommand
	supervisor  Supervisor
	start       coreStarter
	synchronize func(context.Context, CoreDesiredState) error
	desired     CoreDesiredState
	state       CoreState
	startCount  uint32
	lastError   error
	cancel      context.CancelFunc
	done        chan struct{}
	result      error
	logger      *slog.Logger
}

// NewCoreController creates a controller that launches the configured Rust
// Core binary.
func NewCoreController(config CoreCommand, policy RestartPolicy) *CoreController {
	if policy.MaxAttempts == 0 {
		policy = DefaultRestartPolicy()
	}
	controller := newCoreController(config, policy, func(ctx context.Context, config CoreCommand) (CoreProcess, error) {
		return StartCore(ctx, config)
	})
	controller.synchronize = func(ctx context.Context, desired CoreDesiredState) error {
		return (CoreSynchronizer{Client: Client{SocketPath: config.SocketPath}}).Synchronize(ctx, desired)
	}
	return controller
}

func newCoreController(config CoreCommand, policy RestartPolicy, start coreStarter) *CoreController {
	return &CoreController{
		config:     config,
		supervisor: Supervisor{Policy: policy},
		start:      start,
		desired:    NewCoreDesiredState(),
		state:      CoreStopped,
		logger:     coreOperationalLogger(),
	}
}

// SetLogger enables structured lifecycle logging for this controller. Events
// contain only state names, counters, and bounded outcome metadata; secrets,
// packet contents, and user identifiers are never emitted by the controller.
func (controller *CoreController) SetLogger(logger *slog.Logger) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if logger == nil {
		controller.logger = coreOperationalLogger()
		return
	}
	controller.logger = logger
}

func (controller *CoreController) operationalLogger() *slog.Logger {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.logger
}

// SetConfiguration stores network policy for initial startup and every Core
// restart. It does not include any secret or key material.
func (controller *CoreController) SetConfiguration(configuration protocol.NetworkConfiguration) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.desired.SetConfiguration(configuration)
}

// ApprovePeer stores an approved peer for initial startup and every Core
// restart. PeerRegistration intentionally contains no private key material.
func (controller *CoreController) ApprovePeer(peer protocol.PeerRegistration) {
	controller.mu.Lock()
	controller.desired.RegisterPeer(peer)
	logger := controller.logger
	controller.mu.Unlock()
	logCoreEvent(logger, "peer_approval_updated", "peer_id", peer.PeerID)
}

// RevokePeer removes a peer from the state that will be restored after a Core
// restart.
func (controller *CoreController) RevokePeer(peerID uint64) {
	controller.mu.Lock()
	controller.desired.RemovePeer(peerID)
	logger := controller.logger
	controller.mu.Unlock()
	logCoreEvent(logger, "peer_approval_revoked", "peer_id", peerID)
}

// ApplyPeerApproval records an approval and applies it immediately when Core
// is running. The approval remains in desired state if the live IPC call
// fails, so a later Core restart can retry the synchronization.
func (controller *CoreController) ApplyPeerApproval(ctx context.Context, peer protocol.PeerRegistration, requestID uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	controller.ApprovePeer(peer)
	controller.mu.Lock()
	state := controller.state
	socketPath := controller.config.SocketPath
	controller.mu.Unlock()
	if state != CoreRunning {
		return nil
	}
	if requestID == ^uint64(0) {
		return ErrCoreRequestIDExhausted
	}
	if _, err := (Client{SocketPath: socketPath}).RegisterPeer(requestID, peer); err != nil {
		return fmt.Errorf("register approved peer in Core: %w", err)
	}
	return nil
}

// RevokePeerApproval removes an approval and asks Core to revoke it when the
// process is running. Rust Core also closes sessions owned by that peer.
func (controller *CoreController) RevokePeerApproval(ctx context.Context, peerID, requestID uint64) error {
	return controller.removePeerApproval(ctx, peerID, requestID, "peer_approval_revoked")
}

// PurgePeerKey permanently removes the currently approved client identity
// from desired state and the running Core. It is intentionally separate from
// connection revocation so management callers cannot treat key destruction as
// a temporary disconnect.
func (controller *CoreController) PurgePeerKey(ctx context.Context, peerID, requestID uint64) error {
	return controller.removePeerApproval(ctx, peerID, requestID, "peer_key_purged")
}

func (controller *CoreController) removePeerApproval(ctx context.Context, peerID, requestID uint64, event string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	controller.mu.Lock()
	controller.desired.RemovePeer(peerID)
	state := controller.state
	socketPath := controller.config.SocketPath
	logger := controller.logger
	controller.mu.Unlock()
	logCoreEvent(logger, event, "peer_id", peerID)
	if state != CoreRunning {
		return nil
	}
	if _, err := (Client{SocketPath: socketPath}).RemovePeer(requestID, peerID); err != nil {
		return fmt.Errorf("revoke peer in Core: %w", err)
	}
	return nil
}

// DesiredState returns an isolated, secret-free synchronization snapshot.
func (controller *CoreController) DesiredState() CoreDesiredState {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.desired.Snapshot()
}

// Start begins Core supervision and returns once the monitor is installed.
func (controller *CoreController) Start(ctx context.Context) error {
	controller.mu.Lock()
	if controller.state != CoreStopped && controller.state != CoreUnhealthy {
		controller.mu.Unlock()
		return ErrCoreAlreadyStarted
	}
	runContext, cancel := context.WithCancel(ctx)
	controller.cancel = cancel
	controller.done = make(chan struct{})
	controller.result = nil
	controller.lastError = nil
	controller.state = CoreStarting
	logger := controller.logger
	controller.mu.Unlock()
	logCoreEvent(logger, "core_start_requested")
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
		previousState := stateName(controller.state)
		controller.state = CoreStopped
		logger := controller.logger
		controller.mu.Unlock()
		logCoreEvent(logger, "core_stop_completed", "previous_state", previousState)
		return nil
	}
	if controller.cancel == nil || controller.done == nil {
		controller.mu.Unlock()
		return ErrCoreNotStarted
	}
	controller.state = CoreStopping
	previousState := stateName(controller.state)
	cancel := controller.cancel
	done := controller.done
	logger := controller.logger
	controller.mu.Unlock()
	cancel()
	<-done
	logCoreEvent(logger, "core_stop_completed", "previous_state", previousState)
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

// CollectMetrics retrieves an operational snapshot from a running Core.
// requestID and requestID+1 identify the health and metrics IPC calls.
func (controller *CoreController) CollectMetrics(ctx context.Context, requestID uint64) (CoreMetricsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return CoreMetricsSnapshot{}, err
	}
	controller.mu.Lock()
	state := controller.state
	socketPath := controller.config.SocketPath
	controller.mu.Unlock()
	if state != CoreRunning || socketPath == "" || requestID == ^uint64(0) {
		return CoreMetricsSnapshot{}, ErrCoreMetricsUnavailable
	}
	client := Client{SocketPath: socketPath}
	health, err := client.GetHealth(requestID)
	if err != nil {
		return CoreMetricsSnapshot{}, fmt.Errorf("get Core health: %w", err)
	}
	metrics, err := client.GetMetrics(requestID + 1)
	if err != nil {
		return CoreMetricsSnapshot{}, fmt.Errorf("get Core metrics: %w", err)
	}
	return CoreMetricsSnapshot{Health: health, Metrics: metrics}, nil
}

func (controller *CoreController) run(ctx context.Context) {
	result := controller.supervisor.Run(ctx, func() (CoreProcess, error) {
		logCoreEvent(controller.operationalLogger(), "core_start_attempt")
		process, err := controller.start(ctx, controller.config)
		if err != nil {
			logCoreEvent(controller.operationalLogger(), "core_start_failed")
			return nil, err
		}
		if controller.synchronize != nil {
			controller.mu.Lock()
			desired := controller.desired.Snapshot()
			controller.mu.Unlock()
			if err := controller.synchronize(ctx, desired); err != nil {
				_ = process.Stop()
				logCoreEvent(controller.operationalLogger(), "core_state_sync_failed")
				return nil, err
			}
		}
		controller.mu.Lock()
		controller.startCount++
		controller.state = CoreRunning
		startCount := controller.startCount
		controller.mu.Unlock()
		logCoreEvent(controller.operationalLogger(), "core_running", "start_count", startCount)
		return process, nil
	})

	controller.mu.Lock()
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
	state := controller.state
	logger := controller.logger
	logCoreEvent(logger, "core_state_changed", "state", stateName(state), "failure", result != nil && !errors.Is(result, context.Canceled))
	close(controller.done)
	controller.mu.Unlock()
}

func stateName(state CoreState) string {
	switch state {
	case CoreStopped:
		return "stopped"
	case CoreStarting:
		return "starting"
	case CoreRunning:
		return "running"
	case CoreStopping:
		return "stopping"
	case CoreUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}
