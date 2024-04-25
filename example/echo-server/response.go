package main

import (
	"log"

	"github.com/dreadl0ck/tlsx"
	"github.com/wi1dcard/fingerproxy/pkg/ja3"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
)

// echoResponse is the HTTP response struct of this echo server
type echoResponse struct {
	Detail *detailResponse `json:"detail,omitempty"`
	JA3    string          `json:"ja3"`
	JA4    string          `json:"ja4"`
	HTTP2  string          `json:"http2"`

	log *log.Logger
}

type detailResponse struct {
	Metadata      *metadata.Metadata     `json:"metadata"`
	UserAgent     string                 `json:"user-agent"`
	JA3           *tlsx.ClientHelloBasic `json:"ja3"`
	JA3WithoutMD5 string                 `json:"ja3-without-md5"`
	JA4           *ja4.JA4Fingerprint    `json:"ja4"`
}

func (response *echoResponse) fingerprintJA3() error {
	detail := response.Detail
	detail.JA3 = &tlsx.ClientHelloBasic{}
	err := detail.JA3.Unmarshal(detail.Metadata.ClientHelloRecord)
	if err != nil {
		return err
	}

	ja3Raw := ja3.Bare(detail.JA3)
	detail.JA3WithoutMD5 = string(ja3Raw)
	response.JA3 = ja3.BareToDigestHex(ja3Raw)

	response.logf("ja3: %s", response.JA3)
	return nil
}

func (response *echoResponse) fingerprintJA4() error {
	detail := response.Detail
	detail.JA4 = &ja4.JA4Fingerprint{}
	err := detail.JA4.UnmarshalBytes(detail.Metadata.ClientHelloRecord, 't')
	if err != nil {
		return err
	}

	response.JA4 = detail.JA4.String()

	response.logf("ja4: %s", response.JA4)
	return nil
}

func (response *echoResponse) fingerrpintHTTP2() {
	protocol := response.Detail.Metadata.ConnectionState.NegotiatedProtocol
	if protocol == "h2" {
		response.HTTP2 = response.Detail.Metadata.HTTP2Frames.String()
		response.logf("http2: %s", response.HTTP2)
	} else if *flagVerbose {
		response.logf("protocol is %s, skipping HTTP2 fingerprinting", protocol)
	}
}

func (response *echoResponse) logf(format string, args ...any) {
	if !*flagQuiet {
		response.log.Printf(format, args...)
	}
}
