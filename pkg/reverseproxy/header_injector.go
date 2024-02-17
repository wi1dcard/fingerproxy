package reverseproxy

import "net/http"

type HeaderInjector interface {
	GetHeaderName() string

	GetHeaderValue(req *http.Request) (string, error)
}
