package hack

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

type TLSClientHelloConn struct {
	Conn              *tls.Conn
	ClientHelloRecord []byte
	Done              context.CancelFunc
}

func (c *TLSClientHelloConn) Read(b []byte) (n int, err error)  { return c.Conn.Read(b) }
func (c *TLSClientHelloConn) Write(b []byte) (n int, err error) { return c.Conn.Write(b) }
func (c *TLSClientHelloConn) Close() error {
	c.Done()
	return c.Conn.Close()
}
func (c *TLSClientHelloConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *TLSClientHelloConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }
func (c *TLSClientHelloConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *TLSClientHelloConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *TLSClientHelloConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
