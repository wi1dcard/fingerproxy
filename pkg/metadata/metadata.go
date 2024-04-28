// Package `metadata` has a struct that stores information captured by
// `proxyserver`. Package `fingerprint` uses these information to create
// fingerprints.
package metadata

import "crypto/tls"

// Metadata is the data we captured from the connection for fingerprinting.
// Currently only TLS ClientHello and certain HTTP2 frames included, more can
// be added in the future.
type Metadata struct {
	// ClientHelloRecord is the raw TLS ClientHello bytes that
	// include TLS record header and handshake header
	ClientHelloRecord []byte

	// ConnectionState represents the TLS connection state
	ConnectionState tls.ConnectionState

	// HTTP2Frames includes certain HTTP2 frames data
	HTTP2Frames HTTP2FingerprintingFrames
}
