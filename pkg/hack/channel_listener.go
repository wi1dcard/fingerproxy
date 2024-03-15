package hack

import (
	"context"
	"fmt"
	"net"
)

func NewChannelListener(ctx context.Context) *ChannelListener {
	ln := &ChannelListener{
		channel: make(chan net.Conn),
	}
	ln.context, ln.stop = context.WithCancel(ctx)
	return ln
}

type ChannelListener struct {
	channel chan net.Conn
	context context.Context
	stop    context.CancelFunc
}

func (ln *ChannelListener) SendToChannel(conn net.Conn) {
	ln.channel <- conn
}

func (ln *ChannelListener) Accept() (net.Conn, error) {
	select {
	case <-ln.context.Done():
		return nil, ln.context.Err()
	case conn, ok := <-ln.channel:
		if ok {
			return conn, nil
		} else {
			return nil, fmt.Errorf("channel listener: internal channel closed")
		}
	}
}

func (ln *ChannelListener) Close() error {
	ln.stop()
	return nil
}

func (ln *ChannelListener) Addr() net.Addr { return nil }
