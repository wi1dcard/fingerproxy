package proxyserver

import (
	"fmt"

	"github.com/wi1dcard/fingerproxy/pkg/hack"
)

const (
	recordTypeHandshake = 0x16
	recordHeaderLen     = 5
)

func captureClientHelloRecord(bufconn *hack.BufferedConn) ([]byte, error) {
	// https://tls12.xargs.org/#client-hello/annotated
	tlsRecord, err := bufconn.Reader.Peek(1)
	if err != nil {
		return nil, err
	}

	if tlsRecord[0] != recordTypeHandshake {
		return nil, fmt.Errorf("bad request from: %s", bufconn.Conn.RemoteAddr())
	}

	if tlsRecord, err = bufconn.Reader.Peek(recordHeaderLen); err != nil {
		return nil, fmt.Errorf("reading tls record: %w", err)
	}

	// vers := uint16(tlsRecord[1])<<8 | uint16(tlsRecord[2])
	handshakeLen := int(tlsRecord[3])<<8 | int(tlsRecord[4])

	// TODO: check tlsRecordHeaderLooksLikeHTTP
	// io.WriteString(client, "HTTP/1.0 400 Bad Request\r\n\r\n")

	if tlsRecord, err = bufconn.Reader.Peek(recordHeaderLen + handshakeLen); err != nil {
		return nil, err
	}

	clientHelloRecord := make([]byte, len(tlsRecord))
	copy(clientHelloRecord, tlsRecord)
	return clientHelloRecord, nil
}
