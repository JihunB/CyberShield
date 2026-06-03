//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// makeStopChanUnix returns a channel that is closed when SIGINT or SIGTERM
// is received. Used on macOS and Linux where the OS handles service lifecycle.
func makeStopChanUnix() <-chan struct{} {
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
	}()
	return stop
}
