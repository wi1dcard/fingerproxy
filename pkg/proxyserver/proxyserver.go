package proxyserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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

	// optional, whether enable verbose and debug logs
	VerboseLogs bool

	// optional, prometheus metrics registry
	MetricsRegistry *prometheus.Registry

	// optional, prometheus metrics namespace, aka, prefix
	MetricsPrefix string

	// optional, TLS handshake timeout, default is infinity
	TLSHandshakeTimeout time.Duration

	// optional, requests_total metric
	metricRequestsTotal *prometheus.CounterVec

	// required, immutable base context
	ctx       context.Context
	ctxCancel context.CancelFunc

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

	hijackedConn := hack.NewHijackClientHelloConn(conn)
	hijackedConn.VerboseLogFunc = server.vlogf

	tlsConn := tls.Server(hijackedConn, server.TLSConfig)
	defer tlsConn.Close()

	// attempt to handshake
	if err := server.tlsHandshakeWithTimeout(tlsConn); err != nil {
		// https://github.com/golang/go/blob/release-branch.go1.22/src/net/http/server.go#L1925-L1929
		if re, ok := err.(tls.RecordHeaderError); ok && re.Conn != nil && tlsRecordHeaderLooksLikeHTTP(re.RecordHeader) {
			io.WriteString(re.Conn, "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
		}

		if isNetworkOrClientError(err) {
			server.vlogf("tls handshake failed (%s), client error: %s", conn.RemoteAddr(), err)
		} else {
			server.logf("tls handshake error (%s): %s", conn.RemoteAddr(), err)
		}

		server.metricsRequestsTotalInc("0", "")
		return
	}

	// client hello stored in hajackedConn while reading for real handshake
	rec, err := hijackedConn.GetClientHello()
	if err != nil {
		server.logf("could not read client hello (%s): %s", conn.RemoteAddr(), err)
		server.metricsRequestsTotalInc("0", "")
		return
	}

	server.vlogf("client hello (%s): %x", conn.RemoteAddr(), rec)

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

func (server *Server) tlsHandshakeWithTimeout(tlsConn *tls.Conn) error {
	if server.TLSHandshakeTimeout == 0 {
		return tlsConn.HandshakeContext(server.ctx)
	}

	ctx, cancel := context.WithTimeout(server.ctx, server.TLSHandshakeTimeout)
	defer cancel()
	return tlsConn.HandshakeContext(ctx)
}

func updateConnContext(ctx context.Context, c net.Conn) context.Context {
	ctx, md := metadata.NewContext(ctx)
	if conn, ok := c.(*hack.TLSClientHelloConn); ok {
		md.ClientHelloRecord = conn.ClientHelloRecord
		md.ConnectionState = conn.Conn.ConnectionState()
	}
	return ctx
}

func (server *Server) serveHTTP1() {
	err := server.HTTPServer.Serve(server.http1ConnChannelListener)

	if errors.Is(err, context.Canceled) {
		// hack.ChannelListener.Accept() returns context canceled,
		// means our server is shutting down
		return
	}

	if errors.Is(err, http.ErrServerClosed) {
		// ErrServerClosed means internal HTTP server is shutting down,
		// if our server is not shutting down, then shut it down
		if !server.shuttingDown() {
			server.ctxCancel()
		}
		return
	}

	// Here should be impossible
	panic(err)
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
		go server.serveHTTP1()
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
	if server.MetricsRegistry == nil || server.metricsRegistered() {
		return
	}
	pm := promauto.With(server.MetricsRegistry)

	prefix := server.MetricsPrefix
	if prefix == "" {
		prefix = defaultMetricsPrefix
	}

	server.metricRequestsTotal = pm.NewCounterVec(prometheus.CounterOpts{
		Namespace: prefix,
		Name:      "requests_total",
		Help:      "The total number of requests processed by fingerproxy",
	}, []string{"ok", "negotiated_protocol"})

	// ...
}

func (server *Server) logf(format string, args ...any) {
	if server.ErrorLog != nil {
		server.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (server *Server) vlogf(format string, args ...any) {
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
		TLSConfig: tlsConfig,

		HTTPServer: &http.Server{
			Handler: handler,
		},
		HTTP2Server: &http2.Server{},
	}

	server.ctx, server.ctxCancel = context.WithCancel(ctx)

	return server
}

// https://github.com/golang/go/blob/release-branch.go1.22/src/net/http/server.go#L3826-L3834
func tlsRecordHeaderLooksLikeHTTP(hdr [5]byte) bool {
	switch string(hdr[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

func isNetworkOrClientError(err error) bool {
	var netOpErr *net.OpError
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		// https://github.com/golang/go/blob/release-branch.go1.22/src/crypto/tls/conn.go#L724
		(errors.As(err, &netOpErr) && netOpErr.Op == "remote error")
}
