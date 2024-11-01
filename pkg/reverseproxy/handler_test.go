package reverseproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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

const (
	dummyRemoteIP     = "1.1.1.1"
	dummyForwardedFor = "172.17.0.1"
)

func dummyRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://dummy-host/anything?show_env=1", nil)
	req.RemoteAddr = dummyRemoteIP + ":30000"
	req.Header.Set("User-Agent", "dummy")
	req.Header.Set("X-Forwarded-For", dummyForwardedFor)
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

	w := &dummyResponseWriter{}
	handler.ServeHTTP(w, dummyRequest(t))

	j := struct {
		Headers struct {
			Dummy string
			Host  string
		}
	}{}

	t.Log(w.buf.String())

	err := json.Unmarshal(w.buf.Bytes(), &j)
	if err != nil {
		t.Fatal(err)
	}

	if j.Headers.Host != "httpbin.org" {
		t.Fatalf("expected header value %s, actual %s", "httpbin.org", j.Headers.Host)
	}

	if j.Headers.Dummy != "dummy-value" {
		t.Fatalf("expected header value %s, actual %s", "dummy-value", j.Headers.Dummy)
	}
}

func TestPreserveHost(t *testing.T) {
	handler := NewHTTPHandler(dummyURL(t), &httputil.ReverseProxy{}, nil)
	handler.PreserveHost = true

	w := &dummyResponseWriter{}
	handler.ServeHTTP(w, dummyRequest(t))

	j := struct {
		Headers struct {
			Host string
		}
	}{}

	t.Log(w.buf.String())

	err := json.Unmarshal(w.buf.Bytes(), &j)
	if err != nil {
		t.Fatal(err)
	}

	if j.Headers.Host != "dummy-host" {
		t.Fatalf("expected header value %s, actual %s", "dummy-host", j.Headers.Host)
	}
}

func TestAppendForwardHeader(t *testing.T) {
	handler := NewHTTPHandler(dummyURL(t), &httputil.ReverseProxy{}, nil)

	w := &dummyResponseWriter{}
	handler.ServeHTTP(w, dummyRequest(t))

	j := struct {
		Headers struct {
			XForwardedFor string `json:"x-forwarded-for"`
		}
	}{}

	t.Log(w.buf.String())

	err := json.Unmarshal(w.buf.Bytes(), &j)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(j.Headers.XForwardedFor, "172.17.0.1, 1.1.1.1") {
		t.Fatalf("expected header value %s, actual %s", "dummy-host", j.Headers.XForwardedFor)
	}
}
