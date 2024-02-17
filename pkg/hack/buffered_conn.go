package hack

import (
	"bufio"
	"net"
	"time"
)

type BufferedConn struct {
	Conn   net.Conn
	Reader *bufio.Reader
}

func NewBufferedConn(conn net.Conn) *BufferedConn {
	return &BufferedConn{
		Conn:   conn,
		Reader: bufio.NewReader(conn),
	}
}

func (c *BufferedConn) Read(b []byte) (n int, err error)   { return c.Reader.Read(b) }
func (c *BufferedConn) Write(b []byte) (n int, err error)  { return c.Conn.Write(b) }
func (c *BufferedConn) Close() error                       { return c.Conn.Close() }
func (c *BufferedConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *BufferedConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }
func (c *BufferedConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *BufferedConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *BufferedConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
