package proxyserver

import (
	"fmt"
	"net"
	"testing"
)

func TestIsNetworkOrClientError(t *testing.T) {
	// https://github.com/golang/go/blob/release-branch.go1.22/src/crypto/tls/alert.go#L77
	alert := fmt.Errorf("unknown certificate authority")
	// https://github.com/golang/go/blob/release-branch.go1.22/src/crypto/tls/conn.go#L724
	err := setErrorLocked(&net.OpError{Op: "remote error", Err: alert})
	if isNetworkOrClientError(err) == false {
		t.Error("expected tls alert record is client error, got false")
	}

	if isNetworkOrClientError(fmt.Errorf("some random error")) {
		t.Error("expected random error is not client error, got true")
	}
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		return &permanentError{err: e}
	} else {
		return err
	}
}
