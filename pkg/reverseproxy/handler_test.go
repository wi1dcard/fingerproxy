package reverseproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
)

type dummyResponseWriter struct {
	buf    bytes.Buffer
	code   int
	header http.Header
}

func (w *dummyResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *dummyResponseWriter) WriteHeader(statusCode int)  { w.code = statusCode }
func (w *dummyResponseWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }

func dummyRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://httpbin.org/anything", nil)
	req.Header.Set("User-Agent", "dummy")
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func dummyURL(t *testing.T) *url.URL {
	url, err := url.Parse("https://httpbin.org")
	if err != nil {
		t.Fatal(err)
	}
	return url
}

func TestKubernetesLivenessProbe(t *testing.T) {
	handler := NewHTTPHandler(dummyURL(t), &httputil.ReverseProxy{}, nil)
	handler.IsProbeRequest = IsKubernetesProbeRequest

	req := dummyRequest(t)
	req.Header.Set("User-Agent", "kube-probe/1.26")

	w := &dummyResponseWriter{}
	handler.ServeHTTP(w, req)

	if w.buf.String() != ProbeResponse {
		t.Fatalf("expected response %s, actual %s", ProbeResponse, w.buf.String())
	}
	if w.code != ProbeStatusCode {
		t.Fatalf("expected status code %d, actual %d", ProbeStatusCode, w.code)
	}
}

type dummyHeaderInjector struct{}

func (i *dummyHeaderInjector) GetHeaderName() string { return "dummy" }
func (i *dummyHeaderInjector) GetHeaderValue(req *http.Request) (string, error) {
	return "dummy-value", nil
}

func TestInjectHeader(t *testing.T) {
	hj := &dummyHeaderInjector{}
	handler := NewHTTPHandler(dummyURL(t), &httputil.ReverseProxy{}, []HeaderInjector{hj})
	handler.IsProbeRequest = IsKubernetesProbeRequest

	w := &dummyResponseWriter{}
	handler.ServeHTTP(w, dummyRequest(t))

	j := struct {
		Headers struct {
			Dummy string
		}
	}{}

	t.Log(w.buf.String())

	err := json.Unmarshal(w.buf.Bytes(), &j)
	if err != nil {
		t.Fatal(err)
	}

	if j.Headers.Dummy != "dummy-value" {
		t.Fatalf("expected header value %s, actual %s", "dummy-value", j.Headers.Dummy)
	}
}
