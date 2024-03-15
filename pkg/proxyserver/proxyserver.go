package proxyserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/wi1dcard/fingerproxy/pkg/hack"
	"github.com/wi1dcard/fingerproxy/pkg/http2"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
)

const defaultMetricsPrefix = "fingerproxy"

type Server struct {
	// required, TLS config that including certificates, etc
	TLSConfig *tls.Config

	// required, set to your http.Server if you want to customize
	HTTPServer *http.Server

	// required, set to your http2.Server if you want to customize
	HTTP2Server *http2.Server

	// optional, error logger
	ErrorLog *log.Logger

	// optional, enable verbose and debug logs
	VerboseLogs bool

	// optional, prometheus metrics registry
	MetricsRegistry *prometheus.Registry

	// optional, prometheus metrics namespace, aka, prefix
	MetricsPrefix string

	// optional, requests_total metric
	metricRequestsTotal *prometheus.CounterVec

	// required, immutable base context
	ctx context.Context

	// required, func serveConn sends net.Conn to the channel,
	//           and Server.HTTPServer receives from the channel
	http1ConnChannelListener *hack.ChannelListener

	// required, true when server is in shutdown
	inShutdown atomic.Bool

	// required, mutex for initiating the server
	mu sync.Mutex
}

// Serves the connection once we accepted it
func (server *Server) serveConn(conn net.Conn) {
	defer recover()
	defer conn.Close()

	bufconn := hack.NewBufferedConn(conn)

	// intercept the TLS record (which should be a ClientHello) before real handshake
	rec, err := captureClientHelloRecord(bufconn)
	if err != nil {
		server.logf("%s", err)
		server.metricsRequestsTotalInc("0", "")
		return
	}

	tlsConn := tls.Server(bufconn, server.TLSConfig)
	defer tlsConn.Close()

	// do the real handshake
	if err := tlsConn.HandshakeContext(server.ctx); err != nil {
		server.logf("tls handshake: %s", err)
		server.metricsRequestsTotalInc("0", "")
		return
	}

	cs := tlsConn.ConnectionState()

	// either directly serve the http2 conn, or, send to the channel
	// where the HTTP/1.1 server is listening to
	if cs.NegotiatedProtocol == "h2" {
		ctx, md := metadata.NewContext(server.ctx)
		md.ClientHelloRecord = rec
		md.ConnectionState = cs
		server.HTTP2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
			Context:    ctx,
			BaseConfig: server.HTTPServer,
			Handler:    server.HTTPServer.Handler,
		})
	} else {
		ctx, done := context.WithCancel(context.Background())
		server.http1ConnChannelListener.SendToChannel(&hack.TLSClientHelloConn{
			Done:              done,
			Conn:              tlsConn,
			ClientHelloRecord: rec,
		})
		// wait for the connection to be served by HTTP/1.1 server
		<-ctx.Done()
	}

	server.metricsRequestsTotalInc("1", cs.NegotiatedProtocol)
}

func updateConnContext(ctx context.Context, c net.Conn) context.Context {
	ctx, md := metadata.NewContext(ctx)
	if conn, ok := c.(*hack.TLSClientHelloConn); ok {
		md.ClientHelloRecord = conn.ClientHelloRecord
		md.ConnectionState = conn.Conn.ConnectionState()
	}
	return ctx
}

func (server *Server) setupServe() {
	server.mu.Lock()
	defer server.mu.Unlock()

	// register prometheus metrics
	server.registerMetrics()

	// ensure the context
	if server.ctx == nil {
		server.ctx = context.Background()
	}
	server.HTTPServer.ConnContext = updateConnContext
	server.HTTPServer.BaseContext = func(l net.Listener) context.Context {
		return server.ctx
	}

	// start HTTP/1.1 server
	if server.http1ConnChannelListener == nil {
		server.http1ConnChannelListener = hack.NewChannelListener(server.ctx)
		go server.HTTPServer.Serve(server.http1ConnChannelListener)
	}
}

func (server *Server) Serve(ln net.Listener) error {
	defer ln.Close()

	// ensure http servers
	if server.HTTPServer == nil || server.HTTP2Server == nil {
		return fmt.Errorf("HTTPServer and HTTP2Server must be set")
	}

	// setup
	server.setupServe()

	// handle shutting down
	go func() {
		<-server.ctx.Done()
		server.vlogf("server %s is shutting down...", ln.Addr())
		server.inShutdown.Store(true)
		server.HTTPServer.Shutdown(context.Background())
		ln.Close()
	}()

	// serve
	for {
		conn, err := ln.Accept()
		// TODO: recover from accept error
		if err != nil {
			if server.shuttingDown() {
				return http.ErrServerClosed
			}
			return err
		}

		server.vlogf("new connection from %s", conn.RemoteAddr())
		go server.serveConn(conn)
	}
}

func (server *Server) ListenAndServe(listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	return server.Serve(ln)
}

func (server *Server) metricsRegistered() bool {
	return server.metricRequestsTotal != nil
}

func (server *Server) metricsRequestsTotalInc(ok string, negotiatedProtocol string) {
	if server.metricsRegistered() {
		server.metricRequestsTotal.WithLabelValues(ok, negotiatedProtocol).Inc()
	}
}

func (server *Server) registerMetrics() {
	if server.metricsRegistered() {
		return
	}

	if server.MetricsRegistry == nil {
		return
	}

	prefix := server.MetricsPrefix
	if prefix == "" {
		prefix = defaultMetricsPrefix
	}

	f := promauto.With(server.MetricsRegistry)

	server.metricRequestsTotal = f.NewCounterVec(prometheus.CounterOpts{
		Namespace: prefix,
		Name:      "requests_total",
	}, []string{"ok", "negotiated_protocol"})
}

func (server *Server) logf(format string, args ...any) {
	if server.ErrorLog != nil {
		server.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (server *Server) vlogf(format string, args ...interface{}) {
	if server.VerboseLogs {
		server.logf(format, args...)
	}
}

func (server *Server) shuttingDown() bool {
	return server.inShutdown.Load()
}

// Creates a new proxy server
func NewServer(ctx context.Context, handler http.Handler, tlsConfig *tls.Config) *Server {
	server := &Server{
		ctx:       ctx,
		TLSConfig: tlsConfig,

		HTTPServer: &http.Server{
			Handler: handler,
		},
		HTTP2Server: &http2.Server{},
	}

	return server
}
