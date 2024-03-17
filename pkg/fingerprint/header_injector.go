package fingerprint

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
)

const defaultMetricsPrefix = "fingerproxy"

var (
	// optional, prometheus metrics registry
	MetricsRegistry *prometheus.Registry

	// optional, prometheus metrics namespace, aka, prefix
	MetricsPrefix string

	fingerprintDurationMetric *prometheus.HistogramVec
)

type FingerprintFunc func(*metadata.Metadata) (string, error)

// FingerprintHeaderInjector implements reverseproxy.HeaderInjector
type FingerprintHeaderInjector struct {
	HeaderName                       string
	FingerprintFunc                  FingerprintFunc
	FingerprintDurationSucceedMetric prometheus.Observer
	FingerprintDurationErrorMetric   prometheus.Observer
}

func NewFingerprintHeaderInjector(headerName string, fingerprintFunc FingerprintFunc) *FingerprintHeaderInjector {
	i := &FingerprintHeaderInjector{
		HeaderName:      headerName,
		FingerprintFunc: fingerprintFunc,
	}

	registerMetrics()

	if metricsRegistered() {
		i.FingerprintDurationSucceedMetric = fingerprintDurationMetric.WithLabelValues("1", headerName)
		i.FingerprintDurationErrorMetric = fingerprintDurationMetric.WithLabelValues("0", headerName)
	}

	return i
}

func metricsRegistered() bool {
	return fingerprintDurationMetric != nil
}

func registerMetrics() {
	if MetricsRegistry == nil {
		return
	}
	if metricsRegistered() {
		return
	}

	f := promauto.With(MetricsRegistry)

	fingerprintDurationMetric = f.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: MetricsPrefix,
		Name:      "fingerprint_duration_seconds",
		// TODO: configurable buckets
		Buckets: []float64{.00001, .00002, .00005, .0001, .0002, .0005, .001, .005, .01},
	}, []string{"ok", "header_name"})
}

func (i *FingerprintHeaderInjector) GetHeaderName() string {
	return i.HeaderName
}

func (i *FingerprintHeaderInjector) GetHeaderValue(req *http.Request) (string, error) {
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		return "", fmt.Errorf("failed to get context")
	}

	start := time.Now()
	fp, err := i.FingerprintFunc(data)
	duration := time.Since(start)
	vlogf("fingerprint duration: %s", duration)

	if err == nil {
		if i.FingerprintDurationSucceedMetric != nil {
			i.FingerprintDurationSucceedMetric.Observe(duration.Seconds())
		}
	} else {
		if i.FingerprintDurationErrorMetric != nil {
			i.FingerprintDurationErrorMetric.Observe(duration.Seconds())
		}
	}

	return fp, err
}
