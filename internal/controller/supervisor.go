package controller

import (
	"context"
	"errors"
	"time"
)

var ErrCoreUnhealthy = errors.New("tunnel core remained unhealthy after restart limit")

// CoreProcess is the small lifecycle boundary required by the controller.
type CoreProcess interface {
	Wait() error
	Stop() error
}

// RestartPolicy bounds automatic restarts after unexpected Core exits.
type RestartPolicy struct {
	MaxAttempts uint32
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func (policy RestartPolicy) delay(attempt uint32) time.Duration {
	factor := uint32(1)
	for index := uint32(1); index < attempt; index++ {
		if factor > ^uint32(0)/2 {
			factor = ^uint32(0)
			break
		}
		factor *= 2
	}
	delay := policy.BaseDelay * time.Duration(factor)
	if delay < 0 || delay > policy.MaxDelay {
		return policy.MaxDelay
	}
	return delay
}

// DefaultRestartPolicy uses a finite five-attempt, one-to-thirty-second backoff.
func DefaultRestartPolicy() RestartPolicy {
	return RestartPolicy{MaxAttempts: 5, BaseDelay: time.Second, MaxDelay: 30 * time.Second}
}

// Supervisor keeps the Core alive without retrying forever.
type Supervisor struct {
	Policy RestartPolicy
}

// Run starts and monitors Core processes until one exits normally, the context
// is cancelled, or the bounded restart policy is exhausted.
func (supervisor Supervisor) Run(ctx context.Context, start func() (CoreProcess, error)) error {
	policy := supervisor.Policy
	if policy.MaxAttempts == 0 {
		return ErrCoreUnhealthy
	}
	for attempt := uint32(0); ; attempt++ {
		process, err := start()
		if err != nil {
			if attempt+1 >= policy.MaxAttempts {
				return ErrCoreUnhealthy
			}
			if err := waitForRestart(ctx, policy.delay(attempt+1)); err != nil {
				return err
			}
			continue
		}

		wait := make(chan error, 1)
		go func() { wait <- process.Wait() }()
		select {
		case <-ctx.Done():
			_ = process.Stop()
			return ctx.Err()
		case err := <-wait:
			if err == nil {
				return nil
			}
			if attempt+1 >= policy.MaxAttempts {
				return ErrCoreUnhealthy
			}
			if err := waitForRestart(ctx, policy.delay(attempt+1)); err != nil {
				return err
			}
		}
	}
}

func waitForRestart(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
