//go:build !windows

package main

// windowsServiceMain is a no-op on non-Windows platforms.
// On macOS / Linux the agent is managed by launchd / systemd,
// which handle start/stop signalling automatically.
func windowsServiceMain(run func(stop <-chan struct{})) {
	run(makeStopChanUnix())
}
