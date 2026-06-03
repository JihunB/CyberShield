module github.com/cybershield/agent

go 1.22

require golang.org/x/sys v0.21.0

// golang.org/x/sys provides:
//   - windows/svc           : Windows Service Control Manager integration
//   - windows/svc/debug     : Interactive console runner (mirrors SCM interface)
//   - windows/svc/eventlog  : Windows Event Log writer
//
// On macOS and Linux, only the non-windows build tags are used,
// so this dependency compiles away cleanly on those platforms.
