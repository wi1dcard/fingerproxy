package hack

import (
	"context"
	"net"
)

func NewChannelListener(ctx context.Context, ch chan net.Conn) *ChannelListener {
	ln := &ChannelListener{
		Channel: ch,
	}

	ln.context, ln.stop = context.WithCancel(ctx)
	return ln
}

type ChannelListener struct {
	Channel chan net.Conn
	context context.Context
	stop    context.CancelFunc
}

func (ln *ChannelListener) Accept() (net.Conn, error) {
	select {
	case <-ln.context.Done():
		return nil, ln.context.Err()
	case conn := <-ln.Channel:
		return conn, nil
	}
}

func (ln *ChannelListener) Close() error {
	ln.stop()
	return nil
}

func (ln *ChannelListener) Addr() net.Addr { return nil }
