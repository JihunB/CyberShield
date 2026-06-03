//go:build windows

package main

import (
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const serviceName = "CyberShieldAgent"

// windowsServiceMain is called instead of runAgent() when the process is
// launched by the Windows Service Control Manager (SCM).
// It wraps the agent loop so that SCM receives proper Running / Stopped signals.
func windowsServiceMain(run func(stop <-chan struct{})) {
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("Failed to detect session type: %v", err)
	}

	if isInteractive {
		// Running from terminal — behave like a normal console app
		run(makeStopChan())
		return
	}

	// Running under SCM
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		// Non-fatal — we can still log to file
		elog = nil
	}
	if elog != nil {
		defer elog.Close()
		_ = elog.Info(1, "CyberShield Agent starting")
	}

	if err := svc.Run(serviceName, &windowsHandler{run: run, elog: elog}); err != nil {
		if elog != nil {
			_ = elog.Error(1, "Service failed: "+err.Error())
		}
		log.Fatalf("Service Run failed: %v", err)
	}

	if elog != nil {
		_ = elog.Info(1, "CyberShield Agent stopped")
	}
}

// windowsHandler implements the svc.Handler interface required by the SCM.
type windowsHandler struct {
	run  func(stop <-chan struct{})
	elog *eventlog.Log
}

func (h *windowsHandler) Execute(
	args []string,
	r <-chan svc.ChangeRequest,
	s chan<- svc.Status,
) (svcSpecificEC bool, exitCode uint32) {

	// ── 1. Tell SCM we are starting (within 5 s) ─────────────────────────────
	s <- svc.Status{State: svc.StartPending, WaitHint: 5000}

	// ── 2. Launch the agent loop in the background ───────────────────────────
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.run(stopCh)
	}()

	// Give the agent a moment to initialise before reporting Running.
	// If it panics immediately we'll catch it via done being closed.
	select {
	case <-done:
		// Agent exited unexpectedly during startup
		s <- svc.Status{State: svc.Stopped}
		return false, 1
	case <-time.After(500 * time.Millisecond):
		// Looking good — report Running to SCM
	}

	// ── 3. Report Running ─────────────────────────────────────────────────────
	const acceptCmds = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.Running, Accepts: acceptCmds}

	if h.elog != nil {
		_ = h.elog.Info(1, "CyberShield Agent is running")
	}

	// ── 4. Service control loop ───────────────────────────────────────────────
	for {
		select {
		case <-done:
			// Agent exited on its own
			s <- svc.Status{State: svc.Stopped}
			return false, 0

		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				s <- req.CurrentStatus

			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending, WaitHint: 10000}
				close(stopCh) // signal agent goroutine to stop
				select {
				case <-done:
				case <-time.After(8 * time.Second):
					// Force stop after timeout
				}
				s <- svc.Status{State: svc.Stopped}
				return false, 0

			default:
				if h.elog != nil {
					_ = h.elog.Warning(1, "Unexpected control request")
				}
			}
		}
	}
}

// makeStopChan returns a channel that is closed when the process receives
// a console interrupt (Ctrl-C). Used when running interactively on Windows.
func makeStopChan() <-chan struct{} {
	stop := make(chan struct{})
	// We re-use the debug runner which listens for Ctrl-C
	go func() {
		_ = debug.Run(serviceName, &windowsHandler{
			run:  func(s <-chan struct{}) { <-s },
			elog: nil,
		})
		close(stop)
	}()
	return stop
}
