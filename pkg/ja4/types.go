package ja4

import (
	"fmt"

	utls "github.com/refraction-networking/utls"
)

type (
	tlsVersion           uint16
	numberOfCipherSuites int
	numberOfExtensions   int
	firstALPN            string

	cipherSuites        []uint16
	extensions          []uint16
	signatureAlgorithms []uint16
)

func (x tlsVersion) String() string {
	switch uint16(x) {
	case utls.VersionTLS10:
		return "10"
	case utls.VersionTLS11:
		return "11"
	case utls.VersionTLS12:
		return "12"
	case utls.VersionTLS13:
		return "13"
	}
	return "00"
}
func (x numberOfCipherSuites) String() string { return fmt.Sprintf("%02d", x) }
func (x numberOfExtensions) String() string   { return fmt.Sprintf("%02d", x) }
func (x firstALPN) String() string {
	switch string(x) {
	case "http/1.1":
		return "h1"
	case "h2":
		return "h2"
	}
	return "00"
}
func (x cipherSuites) String() string        { return joinUint16(x, cipherSuitesSeparator) }
func (x extensions) String() string          { return joinUint16(x, extensionsSeparator) }
func (x signatureAlgorithms) String() string { return joinUint16(x, signatureAlgorithmSeparator) }
