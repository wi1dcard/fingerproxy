// Package hack includes wraps and hacks of Go net stack.
package hack

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	recordTypeHandshake = 0x16
	recordHeaderLen     = 5
)

var (
	ErrIncompleteClientHello = errors.New("incomplete client hello")
)

type HijackClientHelloConn struct {
	// internal tls.Conn
	tlsConn net.Conn

	// client hello stored in buf
	buf bytes.Buffer

	// expected length of the TLS client hello record
	expectedLen uint16

	// verbose log func
	VerboseLogFunc func(string, ...any)
}

func NewHijackClientHelloConn(conn net.Conn) *HijackClientHelloConn {
	return &HijackClientHelloConn{
		tlsConn: conn,
	}
}

func (c *HijackClientHelloConn) Read(b []byte) (int, error) {
	n, err := c.tlsConn.Read(b)
	if err == nil {
		if c.hasCompleteClientHello() {
			c.vlogf("got %d bytes, but client hello is already mature, skipping hijack", n)
		} else {
			c.hijackClientHello(b[:n])
		}
	}
	return n, err
}

func (c *HijackClientHelloConn) hasCompleteClientHello() bool {
	bufLen := c.buf.Len()
	if bufLen == 0 || c.expectedLen == 0 {
		return false
	}
	if bufLen < int(c.expectedLen) {
		return false
	}
	if bufLen > int(c.expectedLen) {
		// if buffer content is longer than we need,
		// cut it to expected len
		c.buf.Truncate(int(c.expectedLen))
		c.vlogf("truncated buffer from %d to %d bytes", bufLen, c.expectedLen)
	}
	return true
}

func (c *HijackClientHelloConn) hijackClientHello(b []byte) {
	c.buf.Write(b)
	c.vlogf("wrote %d bytes, total %d bytes", len(b), c.buf.Len())

	// ignores the error which should be impossible
	_ = c.tryParseClientHello()
}

func (c *HijackClientHelloConn) tryParseClientHello() error {
	if c.hasCompleteClientHello() {
		c.vlogf("client hello is mature, skipping parse")
		return nil
	}

	bufBytes := c.buf.Bytes()
	bufLen := c.buf.Len()
	if bufLen < 5 {
		c.vlogf("buffer too short (%d bytes), skipping parse", bufLen)
		return ErrIncompleteClientHello
	}

	recType := bufBytes[0]
	if recType != recordTypeHandshake {
		return fmt.Errorf("tls record type 0x%x is not a handshake", recType)
	}

	vers := uint16(bufBytes[1])<<8 | uint16(bufBytes[2])
	if vers < tls.VersionSSL30 || vers > tls.VersionTLS13 {
		return fmt.Errorf("unknown tls version: 0x%x", vers)
	}

	handshakeLen := uint16(bufBytes[3])<<8 | uint16(bufBytes[4])
	c.expectedLen = recordHeaderLen + handshakeLen

	// call hasCompleteClientHello to truncate the buffer if possible
	if c.hasCompleteClientHello() {
		c.vlogf("client hello is mature after got record length")
		return nil
	} else {
		return ErrIncompleteClientHello
	}
}

func (c *HijackClientHelloConn) GetClientHello() ([]byte, error) {
	if err := c.tryParseClientHello(); err != nil {
		return nil, err
	}
	return c.buf.Bytes(), nil
}

func (c *HijackClientHelloConn) vlogf(format string, args ...any) {
	if c.VerboseLogFunc != nil {
		c.VerboseLogFunc(format, args...)
	}
}

/*
implement net.Conn begin ...
*/

func (c *HijackClientHelloConn) Write(b []byte) (n int, err error) { return c.tlsConn.Write(b) }
func (c *HijackClientHelloConn) Close() error                      { return c.tlsConn.Close() }
func (c *HijackClientHelloConn) LocalAddr() net.Addr               { return c.tlsConn.LocalAddr() }
func (c *HijackClientHelloConn) RemoteAddr() net.Addr              { return c.tlsConn.RemoteAddr() }
func (c *HijackClientHelloConn) SetDeadline(t time.Time) error     { return c.tlsConn.SetDeadline(t) }
func (c *HijackClientHelloConn) SetReadDeadline(t time.Time) error {
	return c.tlsConn.SetReadDeadline(t)
}
func (c *HijackClientHelloConn) SetWriteDeadline(t time.Time) error {
	return c.tlsConn.SetWriteDeadline(t)
}

/*
... implement net.Conn end
*/
