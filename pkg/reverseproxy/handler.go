package reverseproxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type HTTPHandler struct {
	// required, the URL that requests will be forwarding to
	To *url.URL

	// required, internal reverse proxy that forwards the requests
	ReverseProxy *httputil.ReverseProxy

	// optional, preserve the host in outbound requests
	PreserveHost bool

	// optional, but in fact required, injecting fingerprint headers to outbound requests
	HeaderInjectors []HeaderInjector
}

func NewHTTPHandler(to *url.URL, reverseProxy *httputil.ReverseProxy, headerInjectors []HeaderInjector) *HTTPHandler {
	f := &HTTPHandler{
		To:              to,
		HeaderInjectors: headerInjectors,
		ReverseProxy:    reverseProxy,
	}

	f.SetReverseProxyRewriteFunc()
	return f
}

func (f *HTTPHandler) SetReverseProxyRewriteFunc() {
	f.ReverseProxy.Rewrite = f.rewriteFunc
}

func (f *HTTPHandler) rewriteFunc(r *httputil.ProxyRequest) {
	r.SetURL(f.To)
	r.SetXForwarded()

	if f.PreserveHost {
		r.Out.Host = r.In.Host
	}

	for _, hj := range f.HeaderInjectors {
		k := hj.GetHeaderName()
		if v, err := hj.GetHeaderValue(r.In); err != nil {
			f.logf("get header %s value for %s failed: %s", k, r.In.RemoteAddr, err)
		} else if v != "" { // skip empty header values
			r.Out.Header.Set(k, v)
		}
	}
}

func (f *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// TODO: add liveness probe
	f.ReverseProxy.ServeHTTP(w, req)
}

func (f *HTTPHandler) logf(format string, args ...any) {
	if f.ReverseProxy.ErrorLog != nil {
		f.ReverseProxy.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
