//go:build !debug

package debug

// Do nothing when build without build tag `debug`.
func StartDebugServer() {}
