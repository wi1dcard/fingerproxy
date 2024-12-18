package fingerproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/wi1dcard/fingerproxy/pkg/certwatcher"
	"github.com/wi1dcard/fingerproxy/pkg/debug"
	fp "github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
	"github.com/wi1dcard/fingerproxy/pkg/reverseproxy"
)

const logFlags = log.LstdFlags | log.Lshortfile | log.Lmsgprefix

var (
	// values are from CI build
	BuildCommit = "GIT_COMMIT_PLACEHOLDER"
	BuildTag    = "GIT_TAG_PLACEHOLDER"
)

var (
	// The loggers used by fingerproxy components

	ProxyServerLog  = log.New(os.Stderr, "[proxyserver] ", logFlags)
	HTTPServerLog   = log.New(os.Stderr, "[http] ", logFlags)
	PrometheusLog   = log.New(os.Stderr, "[metrics] ", logFlags)
	ReverseProxyLog = log.New(os.Stderr, "[reverseproxy] ", logFlags)
	FingerprintLog  = log.New(os.Stderr, "[fingerprint] ", logFlags)
	CertWatcherLog  = log.New(os.Stderr, "[certwatcher] ", logFlags)
	DefaultLog      = log.New(os.Stderr, "[fingerproxy] ", logFlags)

	// The Prometheus metric registry used by fingerproxy
	PrometheusRegistry = prometheus.NewRegistry()

	// The header injectors that injects fingerprint headers to forwarding requests,
	// defaults to [fingerproxy.DefaultHeaderInjectors]
	GetHeaderInjectors = DefaultHeaderInjectors
)

// DefaultHeaderInjectors is the default header injector set that injects JA3, JA4,
// and Akamai HTTP2 fingerprints. Override [fingerproxy.GetHeaderInjectors] to replace
// this to your own injectors.
func DefaultHeaderInjectors() []reverseproxy.HeaderInjector {
	h2fp := &fp.HTTP2FingerprintParam{}
	if flagMaxHTTP2PriorityFrames == nil { // if CLI flags are not initialized
		h2fp.MaxPriorityFrames = math.MaxUint
	} else {
		h2fp.MaxPriorityFrames = *flagMaxHTTP2PriorityFrames
	}

	return []reverseproxy.HeaderInjector{
		fp.NewFingerprintHeaderInjector("X-JA3-Fingerprint", fp.JA3Fingerprint),
		fp.NewFingerprintHeaderInjector("X-JA4-Fingerprint", fp.JA4Fingerprint),
		fp.NewFingerprintHeaderInjector("X-HTTP2-Fingerprint", h2fp.HTTP2Fingerprint),
	}
}

func proxyErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	ReverseProxyLog.Printf("proxy %s error (from %s): %v", req.URL.String(), req.RemoteAddr, err)

	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		rw.WriteHeader(http.StatusGatewayTimeout)
	} else {
		rw.WriteHeader(http.StatusBadGateway)
	}
}

func defaultReverseProxyHTTPHandler(forwardTo *url.URL, headerInjectors []reverseproxy.HeaderInjector) http.Handler {
	handler := reverseproxy.NewHTTPHandler(
		forwardTo,
		&httputil.ReverseProxy{
			ErrorLog:      ReverseProxyLog,
			FlushInterval: parseReverseProxyFlushInterval(),
			ErrorHandler:  proxyErrorHandler,
			// TODO: customize transport
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		headerInjectors,
	)

	handler.PreserveHost = *flagPreserveHost

	if *flagEnableKubernetesProbe {
		handler.IsProbeRequest = reverseproxy.IsKubernetesProbeRequest
	}

	return handler
}

func defaultProxyServer(ctx context.Context, handler http.Handler, tlsConfig *tls.Config) *proxyserver.Server {
	svr := proxyserver.NewServer(ctx, handler, tlsConfig)

	svr.VerboseLogs = *flagVerboseLogs
	svr.ErrorLog = ProxyServerLog
	svr.HTTPServer.ErrorLog = HTTPServerLog

	svr.MetricsRegistry = PrometheusRegistry

	svr.HTTPServer.IdleTimeout = parseHTTPIdleTimeout()
	svr.HTTPServer.ReadTimeout = parseHTTPReadTimeout()
	svr.HTTPServer.WriteTimeout = parseHTTPWriteTimeout()
	svr.TLSHandshakeTimeout = parseTLSHandshakeTimeout()

	return svr
}

func initCertWatcher() *certwatcher.CertWatcher {
	certwatcher.Logger = CertWatcherLog
	certwatcher.VerboseLogs = *flagVerboseLogs
	cw, err := certwatcher.New(*flagCertFilename, *flagKeyFilename)
	if err != nil {
		DefaultLog.Fatalf(`invalid cert filename "%s" or certkey filename "%s": %s`, *flagCertFilename, *flagKeyFilename, err)
	}
	return cw
}

func defaultTLSConfig(cw *certwatcher.CertWatcher) *tls.Config {
	return &tls.Config{
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: cw.GetCertificate,
	}
}

func initFingerprint() {
	fp.Logger = FingerprintLog
	fp.VerboseLogs = *flagVerboseLogs
	fp.RegisterDurationMetric(PrometheusRegistry, parseDurationMetricBuckets(), "")
}

// Run fingerproxy. To customize the fingerprinting algorithms, use "header injectors".
// See [fingerproxy.GetHeaderInjectors] for more info.
func Run() {
	// CLI
	initFlags()
	parseFlags()

	// fingerprint package
	initFingerprint()

	// tls cert watcher
	cw := initCertWatcher()

	// signal cancels context
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	// main TLS server
	server := defaultProxyServer(
		ctx,
		defaultReverseProxyHTTPHandler(
			parseForwardURL(),
			GetHeaderInjectors(),
		),
		defaultTLSConfig(cw),
	)

	// start cert watcher
	go cw.Start(ctx)

	// metrics server
	PrometheusLog.Printf("server listening on %s", *flagMetricsListenAddr)
	go http.ListenAndServe(
		*flagMetricsListenAddr,
		promhttp.HandlerFor(PrometheusRegistry, promhttp.HandlerOpts{
			ErrorLog: PrometheusLog,
		}),
	)

	// debug server if binary build with `debug` tag
	debug.StartDebugServer()

	// start the main TLS server
	DefaultLog.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	DefaultLog.Print(err)
}
