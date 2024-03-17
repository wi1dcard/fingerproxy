package fingerproxy

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/wi1dcard/fingerproxy/pkg/debug"
	"github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
	"github.com/wi1dcard/fingerproxy/pkg/reverseproxy"
)

const logFlags = log.LstdFlags | log.Lshortfile | log.Lmsgprefix

const (
	// TODO: expose these values in CLI flags
	HTTPIdleTimeout           = 180 * time.Second
	HTTPReadTimeout           = 60 * time.Second
	HTTPWriteTimeout          = 60 * time.Second
	TLSHandshakeTimeout       = 10 * time.Second
	ReverseProxyFlushInterval = 100 * time.Millisecond
)

var (
	// values from CI build
	BuildCommit = "GIT_COMMIT_PLACEHOLDER"
	BuildTag    = "GIT_TAG_PLACEHOLDER"
)

var (
	ProxyServerLog  = log.New(os.Stderr, "[proxyserver] ", logFlags)
	HTTPServerLog   = log.New(os.Stderr, "[http] ", logFlags)
	PrometheusLog   = log.New(os.Stderr, "[metrics] ", logFlags)
	ReverseProxyLog = log.New(os.Stderr, "[reverseproxy] ", logFlags)
	FingerprintLog  = log.New(os.Stderr, "[fingerprint] ", logFlags)
	DefaultLog      = log.New(os.Stderr, "[fingerproxy] ", logFlags)

	PrometheusRegistry = prometheus.NewRegistry()

	GetHeaderInjectors         = DefaultHeaderInjectors
	GetReverseProxyHTTPHandler = DefaultReverseProxyHTTPHandler
)

func InitFingerprint(verboseLogs bool) {
	fingerprint.VerboseLogs = verboseLogs
	fingerprint.Logger = FingerprintLog
	fingerprint.MetricsRegistry = PrometheusRegistry
}

func DefaultHeaderInjectors() []reverseproxy.HeaderInjector {
	return []reverseproxy.HeaderInjector{
		fingerprint.NewFingerprintHeaderInjector("X-JA3-Fingerprint", fingerprint.JA3Fingerprint),
		fingerprint.NewFingerprintHeaderInjector("X-JA4-Fingerprint", fingerprint.JA4Fingerprint),
		fingerprint.NewFingerprintHeaderInjector("X-HTTP2-Fingerprint", fingerprint.HTTP2Fingerprint),
	}
}

func DefaultTLSConfig(certFile string, keyFile string) (*tls.Config, error) {
	conf := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	if tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, err
	} else {
		conf.Certificates = []tls.Certificate{tlsCert}
	}

	return conf, nil
}

func StartPrometheusClient(listenAddr string) {
	PrometheusLog.Printf("server listening on %s", listenAddr)
	go http.ListenAndServe(listenAddr, promhttp.HandlerFor(PrometheusRegistry, promhttp.HandlerOpts{
		ErrorLog: PrometheusLog,
	}))
}

func DefaultReverseProxyHTTPHandler(forwardTo *url.URL) *reverseproxy.HTTPHandler {
	return reverseproxy.NewHTTPHandler(
		forwardTo,
		&httputil.ReverseProxy{
			ErrorLog:      ReverseProxyLog,
			FlushInterval: ReverseProxyFlushInterval,
			// TODO: customize transport
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		GetHeaderInjectors(),
	)
}

func DefaultProxyServer(handler http.Handler, tlsConfig *tls.Config, verboseLogs bool) *proxyserver.Server {
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	svr := proxyserver.NewServer(ctx, handler, tlsConfig)

	svr.VerboseLogs = verboseLogs
	svr.ErrorLog = ProxyServerLog
	svr.HTTPServer.ErrorLog = HTTPServerLog

	svr.MetricsRegistry = PrometheusRegistry

	svr.HTTPServer.IdleTimeout = HTTPIdleTimeout
	svr.HTTPServer.ReadTimeout = HTTPReadTimeout
	svr.HTTPServer.WriteTimeout = HTTPWriteTimeout
	svr.TLSHandshakeTimeout = TLSHandshakeTimeout

	return svr
}

func Run() {
	flagListenAddr := flag.String(
		"listen-addr",
		envWithDefault("LISTEN_ADDR", ":443"),
		"Listening address, equivalent to $LISTEN_ADDR",
	)

	flagForwardURL := flag.String(
		"forward-url",
		envWithDefault("FORWARD_URL", "http://localhost:80"),
		"Backend URL that the requests will be forwarded to, equivalent to $FORWARD_URL",
	)

	flagCertFilename := flag.String(
		"cert-filename",
		envWithDefault("CERT_FILENAME", "tls.crt"),
		"TLS certificate filename, equivalent to $CERT_FILENAME",
	)
	flagKeyFilename := flag.String(
		"certkey-filename",
		envWithDefault("CERTKEY_FILENAME", "tls.key"),
		"TLS certificate key file name, equivalent to $CERTKEY_FILENAME",
	)

	flagMetricsListenAddr := flag.String(
		"metrics-listen-addr",
		envWithDefault("METRICS_LISTEN_ADDR", ":9035"),
		"Listening address of Prometheus metrics, equivalent to $METRICS_LISTEN_ADDR",
	)

	flagVerboseLogs := flag.Bool("verbose", false, "Enable verbose logs")
	flagVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *flagVersion {
		fmt.Fprintln(os.Stderr, "Fingerproxy - https://github.com/wi1dcard/fingerproxy")
		fmt.Fprintf(os.Stderr, "Version: %s (%s)\n", BuildTag, BuildCommit)
		os.Exit(0)
	}

	forwardTo, err := url.Parse(*flagForwardURL)
	if err != nil {
		DefaultLog.Fatal(err)
	}

	tlsConfig, err := DefaultTLSConfig(*flagCertFilename, *flagKeyFilename)
	if err != nil {
		DefaultLog.Fatal(err)
	}

	InitFingerprint(*flagVerboseLogs)

	server := DefaultProxyServer(
		GetReverseProxyHTTPHandler(forwardTo),
		tlsConfig,
		*flagVerboseLogs,
	)

	StartPrometheusClient(*flagMetricsListenAddr)
	debug.StartDebugServer()

	DefaultLog.Printf("server listening on %s", *flagListenAddr)
	err = server.ListenAndServe(*flagListenAddr)
	DefaultLog.Print(err)
}

func envWithDefault(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}
	return defaultVal
}
