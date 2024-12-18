// Package `fingerprint` reads `metadata` and calculate the JA3, JA4,
// HTTP2 fingerprints, etc.
//
// It also implements `header_injector` interface from package `reverseproxy`,
// which allows passing fingerprints to the backend through the forwarding
// request headers.
package fingerprint

import (
	"fmt"
	"log"

	"github.com/dreadl0ck/tlsx"
	"github.com/wi1dcard/fingerproxy/pkg/ja3"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
)

var (
	VerboseLogs bool
	Logger      *log.Logger
)

func vlogf(format string, args ...any) {
	if VerboseLogs {
		if Logger != nil {
			Logger.Printf(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

// JA4Fingerprint is a FingerprintFunc
func JA4Fingerprint(data *metadata.Metadata) (string, error) {
	fp := &ja4.JA4Fingerprint{}
	err := fp.UnmarshalBytes(data.ClientHelloRecord, 't') // TODO: identify connection protocol
	if err != nil {
		return "", fmt.Errorf("ja4: %w", err)
	}

	vlogf("ja4: %s", fp)
	return fp.String(), nil
}

// JA3Fingerprint is a FingerprintFunc
func JA3Fingerprint(data *metadata.Metadata) (string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(data.ClientHelloRecord); err != nil {
		return "", fmt.Errorf("ja3: %w", err)
	}

	fp := ja3.DigestHex(hellobasic)
	vlogf("ja3: %s", fp)
	return fp, nil
}

type HTTP2FingerprintParam struct {
	MaxPriorityFrames uint
}

// HTTP2Fingerprint is a FingerprintFunc, it creates Akamai HTTP2 fingerprints
// as the suggested format: S[;]|WU|P[,]#|PS[,]
func (p *HTTP2FingerprintParam) HTTP2Fingerprint(data *metadata.Metadata) (string, error) {
	if data.ConnectionState.NegotiatedProtocol == "h2" {
		fp := data.HTTP2Frames.Marshal(p.MaxPriorityFrames)
		vlogf("http2 fingerprint: %s", fp)
		return fp, nil
	}

	vlogf("%s connection, skipping HTTP2 fingerprinting", data.ConnectionState.NegotiatedProtocol)
	return "", nil
}
