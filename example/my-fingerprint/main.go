package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/wi1dcard/fingerproxy"
	"github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
	"github.com/wi1dcard/fingerproxy/pkg/reverseproxy"

	utls "github.com/refraction-networking/utls"
)

func main() {
	fingerproxy.GetHeaderInjectors = func() []reverseproxy.HeaderInjector {
		i := fingerproxy.DefaultHeaderInjectors()
		i = append(i, fingerprint.NewFingerprintHeaderInjector(
			"X-My-Fingerprint",
			SimpleFingerprint,
		))
		return i
	}
	fingerproxy.Run()
}

func SimpleFingerprint(data *metadata.Metadata) (string, error) {
	// parses client hello first
	chs := &utls.ClientHelloSpec{}
	err := chs.FromRaw(data.ClientHelloRecord, true, true)
	if err != nil {
		return "", fmt.Errorf("simple fingerprint: %w", err)
	}

	// prepare fingerprint buffer
	var buf strings.Builder
	for _, e := range chs.Extensions {
		var field string
		switch e := e.(type) {
		// use ALPN in the fingerprint
		case *utls.ALPNExtension:
			field = fmt.Sprintf("alpn:%s", joinAnything(e.AlpnProtocols, ","))

		// use TLS supported version in the fingerprint
		case *utls.SupportedVersionsExtension:
			sv := []string{}
			for _, v := range e.Versions {
				if isGREASEUint16(v) {
					sv = append(sv, "GREASE")
				} else {
					sv = append(sv, strconv.Itoa(int(v)))
				}
			}
			field = fmt.Sprintf("supported_versions:%s", joinAnything(sv, ","))
		}

		// case ...:
		// use any extension in your fingerprint
		// ...

		if field != "" {
			if buf.Len() != 0 {
				// add separator if needed
				buf.WriteString("|")
			}
			// add field
			buf.WriteString(field)
		}
	}

	// return fingerprint string
	return buf.String(), nil
}

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func joinAnything[E any](elems []E, sep string) string {
	var s strings.Builder
	s.WriteString(fmt.Sprint(elems[0]))
	for _, e := range elems[1:] {
		s.WriteString(sep)
		s.WriteString(fmt.Sprint(e))
	}
	return s.String()
}
