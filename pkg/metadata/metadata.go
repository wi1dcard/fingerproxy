package metadata

import "crypto/tls"

// Metadata is the data we captured from the connection for fingerprinting.
// Currently only TLS ClientHello and certain HTTP2 frames included, more could be
// added in the future.
type Metadata struct {
	// ClientHelloRecord is the raw TLS ClientHello bytes that
	// include TLS record header and handshake header
	ClientHelloRecord []byte

	// ConnectionState represents the TLS connection state
	ConnectionState tls.ConnectionState

	// HTTP2Frames includes certain HTTP2 frames data
	HTTP2Frames HTTP2FingerprintingFrames
}
