package fingerproxy

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var (
	flagListenAddr            *string
	flagForwardURL            *string
	flagCertFilename          *string
	flagKeyFilename           *string
	flagMetricsListenAddr     *string
	flagDurationMetricBuckets *string
	flagPreserveHost          *bool
	flagEnableKubernetesProbe *bool
	flagVerboseLogs           *bool
	flagVersion               *bool
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

	flagEnableKubernetesProbe = flag.Bool(
		"enable-kubernetes-probe",
		envWithDefaultBool("ENABLE_KUBERNETES_PROBE", true),
		"Enable kubernetes liveness/readiness probe support, equivalent to $ENABLE_KUBERNETES_PROBE",
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
		DefaultLog.Fatal(err)
	}

	return forwardURL
}

func parseTLSCerts() tls.Certificate {
	tlsCert, err := tls.LoadX509KeyPair(*flagCertFilename, *flagKeyFilename)
	if err != nil {
		DefaultLog.Fatal(err)
	}
	return tlsCert
}

func parseDurationMetricBuckets() []float64 {
	bucketStrings := strings.Split(*flagDurationMetricBuckets, ",")
	buckets := []float64{}

	for _, bucket := range bucketStrings {
		parsedBucket, err := strconv.ParseFloat(strings.Trim(bucket, " "), 64)
		if err != nil {
			DefaultLog.Fatalf("bad duration metric buckets: %s", err)
		}
		buckets = append(buckets, parsedBucket)
	}

	return buckets
}
