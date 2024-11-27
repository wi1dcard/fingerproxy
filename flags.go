package fingerproxy

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	// basic
	flagListenAddr, flagForwardURL *string

	// tls
	flagCertFilename, flagKeyFilename *string

	// metrics
	flagMetricsListenAddr, flagDurationMetricBuckets *string

	// functionality
	flagPreserveHost              *bool
	flagMaxHTTP2PriorityFrames    *uint
	flagEnableKubernetesProbe     *bool
	flagReverseProxyFlushInterval *string

	// timeouts
	flagTimeoutHTTPIdle, flagTimeoutHTTPRead, flagTimeoutHTTPWrite, flagTimeoutTLSHandshake *string

	// misc
	flagVerboseLogs *bool
	flagVersion     *bool
)

func initFlags() {
	flagListenAddr = flag.String(
		"listen-addr",
		envWithDefault("LISTEN_ADDR", ":443"),
		"Listening address, equivalent to $LISTEN_ADDR",
	)

	flagForwardURL = flag.String(
		"forward-url",
		envWithDefault("FORWARD_URL", "http://localhost:80"),
		"Backend URL that the requests will be forwarded to, equivalent to $FORWARD_URL",
	)

	flagCertFilename = flag.String(
		"cert-filename",
		envWithDefault("CERT_FILENAME", "tls.crt"),
		"TLS certificate filename, equivalent to $CERT_FILENAME",
	)

	flagKeyFilename = flag.String(
		"certkey-filename",
		envWithDefault("CERTKEY_FILENAME", "tls.key"),
		"TLS certificate key file name, equivalent to $CERTKEY_FILENAME",
	)

	flagMetricsListenAddr = flag.String(
		"metrics-listen-addr",
		envWithDefault("METRICS_LISTEN_ADDR", ":9035"),
		"Listening address of Prometheus metrics, equivalent to $METRICS_LISTEN_ADDR",
	)

	flagDurationMetricBuckets = flag.String(
		"duration-metric-buckets",
		envWithDefault("DURATION_METRIC_BUCKETS", ".00001, .00002, .00005, .0001, .0002, .0005, .001, .005, .01"),
		"The histogram buckets of duration metric, equivalent to $DURATION_METRIC_BUCKETS",
	)

	flagPreserveHost = flag.Bool(
		"preserve-host",
		envWithDefaultBool("PRESERVE_HOST", false),
		"Forward HTTP Host header from incoming requests to the backend, equivalent to $PRESERVE_HOST",
	)

	flagMaxHTTP2PriorityFrames = flag.Uint(
		"max-h2-priority-frames",
		envWithDefaultUint("MAX_H2_PRIORITY_FRAMES", 10000),
		"Max number of HTTP2 priority frames, set this to avoid too large HTTP2 fingerprints",
	)

	flagEnableKubernetesProbe = flag.Bool(
		"enable-kubernetes-probe",
		envWithDefaultBool("ENABLE_KUBERNETES_PROBE", true),
		"Enable kubernetes liveness/readiness probe support, equivalent to $ENABLE_KUBERNETES_PROBE",
	)

	flagReverseProxyFlushInterval = flag.String(
		"reverse-proxy-flush-interval",
		envWithDefault("REVERSE_PROXY_FLUSH_INTERVAL", "100ms"),
		"See https://pkg.go.dev/net/http/httputil#ReverseProxy.FlushInterval, equivalent to $REVERSE_PROXY_FLUSH_INTERVAL",
	)

	flagTimeoutHTTPIdle = flag.String(
		"timeout-http-idle",
		envWithDefault("TIMEOUT_HTTP_IDLE", "180s"),
		"See https://pkg.go.dev/net/http#Server.IdleTimeout, equivalent to $TIMEOUT_HTTP_IDLE",
	)

	flagTimeoutHTTPRead = flag.String(
		"timeout-http-read",
		envWithDefault("TIMEOUT_HTTP_READ", "60s"),
		"See https://pkg.go.dev/net/http#Server.ReadTimeout, equivalent to $TIMEOUT_HTTP_READ",
	)

	flagTimeoutHTTPWrite = flag.String(
		"timeout-http-write",
		envWithDefault("TIMEOUT_HTTP_WRITE", "60s"),
		"See https://pkg.go.dev/net/http#Server.WriteTimeout, equivalent to $TIMEOUT_HTTP_WRITE",
	)

	flagTimeoutTLSHandshake = flag.String(
		"timeout-tls-handshake",
		envWithDefault("TIMEOUT_TLS_HANDSHAKE", "10s"),
		"Timeout for TLS handshakes, equivalent to $TIMEOUT_TLS_HANDSHAKE",
	)

	flagVerboseLogs = flag.Bool(
		"verbose",
		envWithDefaultBool("VERBOSE", false),
		"Enable verbose logs, equivalent to $VERBOSE",
	)

	flagVersion = flag.Bool("version", false, "Print version and exit")
}

func parseFlags() {
	flag.Parse()

	if *flagVersion {
		fmt.Fprintln(os.Stderr, "Fingerproxy - https://github.com/wi1dcard/fingerproxy")
		fmt.Fprintf(os.Stderr, "Version: %s (%s)\n", BuildTag, BuildCommit)
		os.Exit(0)
	}
}

func parseForwardURL() *url.URL {
	forwardURL, err := url.Parse(*flagForwardURL)
	if err != nil {
		DefaultLog.Fatalf(`invalid forward url "%s": %s`, *flagForwardURL, err)
	}

	return forwardURL
}

func parseDurationMetricBuckets() []float64 {
	bucketStrings := strings.Split(*flagDurationMetricBuckets, ",")
	buckets := []float64{}

	for _, bucket := range bucketStrings {
		parsedBucket, err := strconv.ParseFloat(strings.Trim(bucket, " "), 64)
		if err != nil {
			DefaultLog.Fatalf(`invalid duration metric bucket "%s": %s`, bucket, err)
		}
		buckets = append(buckets, parsedBucket)
	}

	return buckets
}

func parseReverseProxyFlushInterval() time.Duration {
	dur, err := time.ParseDuration(*flagReverseProxyFlushInterval)
	if err != nil {
		DefaultLog.Fatalf(`invalid tls handshake timeout "%s": %s`, *flagReverseProxyFlushInterval, dur)
	}
	return dur
}

func parseHTTPIdleTimeout() time.Duration {
	dur, err := time.ParseDuration(*flagTimeoutHTTPIdle)
	if err != nil {
		DefaultLog.Fatalf(`invalid http idle timeout "%s": %s`, *flagTimeoutHTTPIdle, err)
	}
	return dur
}

func parseHTTPReadTimeout() time.Duration {
	dur, err := time.ParseDuration(*flagTimeoutHTTPRead)
	if err != nil {
		DefaultLog.Fatalf(`invalid http read timeout "%s": %s`, *flagTimeoutHTTPRead, err)
	}
	return dur
}

func parseHTTPWriteTimeout() time.Duration {
	dur, err := time.ParseDuration(*flagTimeoutHTTPWrite)
	if err != nil {
		DefaultLog.Fatalf(`invalid http write timeout "%s": %s`, *flagTimeoutHTTPWrite, err)
	}
	return dur
}

func parseTLSHandshakeTimeout() time.Duration {
	dur, err := time.ParseDuration(*flagTimeoutTLSHandshake)
	if err != nil {
		DefaultLog.Fatalf(`invalid tls handshake timeout "%s": %s`, *flagTimeoutTLSHandshake, err)
	}
	return dur
}
