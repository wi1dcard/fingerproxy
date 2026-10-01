// Package `ja4` implements JA4 algorithm based on [utls].
//
// [utls]: https://github.com/refraction-networking/utls
package ja4

import (
	"errors"
	"fmt"
	"io"

	utls "github.com/refraction-networking/utls"
)

const (
	extensionAndSignatureAlgorithmSeparator = "_"
	cipherSuitesSeparator                   = ","
	extensionsSeparator                     = ","
	signatureAlgorithmSeparator             = ","
	ja4ExtensionSNI                         = 0x0000
	ja4ExtensionALPN                        = 0x0010
	ja4ExtensionPadding                     = 0x0015
	ja4ExtensionSessionTicket               = 0x0023
	ja4ExtensionPreSharedKey                = 0x0029
)

type unmarshalPolicy struct {
	ignoreEphemeralExtensions bool
}

var (
	rawJA4Policy    = unmarshalPolicy{}
	stableJA4Policy = unmarshalPolicy{ignoreEphemeralExtensions: true}
)

type JA4Fingerprint struct {
	//
	// JA4_a
	//

	Protocol             byte
	TLSVersion           tlsVersion
	SNI                  byte
	NumberOfCipherSuites numberOfCipherSuites
	NumberOfExtensions   numberOfExtensions
	FirstALPN            string

	//
	// JA4_b
	//

	CipherSuites cipherSuites

	//
	// JA4_c
	//

	Extensions          extensions
	SignatureAlgorithms signatureAlgorithms
}

// StableJA4Fingerprint computes a canonical JA4 variant that ignores
// connection-state-dependent TLS extensions known to drift across fresh and
// resumed handshakes.
type StableJA4Fingerprint struct {
	JA4Fingerprint
}

func (j *JA4Fingerprint) UnmarshalBytes(clientHelloRecord []byte, protocol byte) error {
	return j.unmarshalBytes(clientHelloRecord, protocol, rawJA4Policy)
}

func (j *StableJA4Fingerprint) UnmarshalBytes(clientHelloRecord []byte, protocol byte) error {
	return j.JA4Fingerprint.unmarshalBytes(clientHelloRecord, protocol, stableJA4Policy)
}

func (j *JA4Fingerprint) unmarshalBytes(clientHelloRecord []byte, protocol byte, policy unmarshalPolicy) error {
	chs := &utls.ClientHelloSpec{}
	// allowBluntMimicry: true
	// realPSK: false
	err := chs.FromRaw(clientHelloRecord, true, false)
	if err != nil {
		return fmt.Errorf("cannot parse client hello: %w", err)
	}
	return j.unmarshal(chs, protocol, policy)
}

func (j *JA4Fingerprint) Unmarshal(chs *utls.ClientHelloSpec, protocol byte) error {
	return j.unmarshal(chs, protocol, rawJA4Policy)
}

func (j *StableJA4Fingerprint) Unmarshal(chs *utls.ClientHelloSpec, protocol byte) error {
	return j.JA4Fingerprint.unmarshal(chs, protocol, stableJA4Policy)
}

func (j *JA4Fingerprint) unmarshal(chs *utls.ClientHelloSpec, protocol byte, policy unmarshalPolicy) error {
	// ja4_a
	j.Protocol = protocol
	j.unmarshalTLSVersion(chs)
	j.unmarshalSNI(chs)
	j.unmarshalNumberOfCipherSuites(chs)
	j.unmarshalFirstALPN(chs)

	// ja4_b
	j.unmarshalCipherSuites(chs, false)

	// ja4_c
	extensions, extensionCount, err := collectExtensions(chs, false, policy.ignoreEphemeralExtensions)
	if err != nil {
		return err
	}
	j.NumberOfExtensions = numberOfExtensions(extensionCount)
	j.Extensions = extensions
	j.unmarshalSignatureAlgorithm(chs)

	return nil
}

func (j *JA4Fingerprint) String() string {
	ja4a := fmt.Sprintf(
		"%s%s%s%s%s%s",
		string(j.Protocol),
		j.TLSVersion,
		string(j.SNI),
		j.NumberOfCipherSuites,
		j.NumberOfExtensions,
		j.FirstALPN,
	)

	ja4b := truncatedSha256(j.CipherSuites.String())

	var ja4c string
	if len(j.SignatureAlgorithms) == 0 {
		ja4c = truncatedSha256(j.Extensions.String())
	} else {
		ja4c = truncatedSha256(fmt.Sprintf("%s_%s", j.Extensions, j.SignatureAlgorithms))
	}

	ja4 := fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)

	return ja4
}

func (j *JA4Fingerprint) unmarshalTLSVersion(chs *utls.ClientHelloSpec) {
	var vers uint16
	if chs.TLSVersMax == 0 {
		// SupportedVersionsExtension found, extract version from extension, ref:
		// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L32
		for _, e := range chs.Extensions {
			if sve, ok := e.(*utls.SupportedVersionsExtension); ok {
				for _, v := range sve.Versions {
					// find the highest non-GREASE version
					if !isGREASEUint16(v) && v > vers {
						vers = v
					}
				}
			}
		}
	} else {
		vers = chs.TLSVersMax
	}

	j.TLSVersion = tlsVersion(vers)
}

func (j *JA4Fingerprint) unmarshalSNI(chs *utls.ClientHelloSpec) {
	for _, e := range chs.Extensions {
		if _, ok := e.(*utls.SNIExtension); ok {
			j.SNI = 'd'
			return
		}
	}
	j.SNI = 'i'
}

func (j *JA4Fingerprint) unmarshalNumberOfCipherSuites(chs *utls.ClientHelloSpec) {
	var n int
	for _, c := range chs.CipherSuites {
		if !isGREASEUint16(c) {
			n++
		}
	}
	j.NumberOfCipherSuites = numberOfCipherSuites(n)
}

func (j *JA4Fingerprint) unmarshalFirstALPN(chs *utls.ClientHelloSpec) {
	var alpn string
	for _, e := range chs.Extensions {
		if a, ok := e.(*utls.ALPNExtension); ok {
			if len(a.AlpnProtocols) > 0 {
				alpn = a.AlpnProtocols[0]
			}
		}
	}
	if alpn == "" {
		j.FirstALPN = "00"
		return
	}
	// https://github.com/FoxIO-LLC/ja4/blob/e7226cb51729f70fce740e615f8b2168ad68f67c/python/ja4.py#L241-L245
	if len(alpn) > 2 {
		alpn = string(alpn[0]) + string(alpn[len(alpn)-1])
	}
	if alpn[0] > 127 {
		alpn = "99"
	}
	j.FirstALPN = alpn
}

// keepOriginalOrder should be false unless keeping the original order of cipher
// suites, ref:
// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L140C52-L140C60
func (j *JA4Fingerprint) unmarshalCipherSuites(chs *utls.ClientHelloSpec, keepOriginalOrder bool) {
	var cipherSuites []uint16
	for _, c := range chs.CipherSuites {
		if isGREASEUint16(c) {
			continue
		}
		cipherSuites = append(cipherSuites, c)
	}
	if !keepOriginalOrder {
		sortUint16(cipherSuites)
	}
	j.CipherSuites = cipherSuites
}

// keepOriginalOrder (-o option) should be false unless keeping SNI and ALPN extension
// and the original order of extensions, ref:
// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L140C52-L140C60
func collectExtensions(chs *utls.ClientHelloSpec, keepOriginalOrder bool, ignoreEphemeral bool) ([]uint16, int, error) {
	var extensions []uint16
	var count int
	for _, e := range chs.Extensions {
		// exclude GREASE extensions
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			continue
		}

		extId, err := extensionID(e)
		if err != nil {
			return nil, 0, err
		}

		if !(ignoreEphemeral && isEphemeralExtension(extId)) {
			count++
		}

		if !keepOriginalOrder {
			// SNI and ALPN extension should not be included, ref:
			// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L79
			if extId == ja4ExtensionSNI {
				continue
			}
			if extId == ja4ExtensionALPN {
				continue
			}
			if ignoreEphemeral && isEphemeralExtension(extId) {
				continue
			}
		}

		extensions = append(extensions, extId)
	}

	if !keepOriginalOrder {
		sortUint16(extensions)
	}
	return extensions, count, nil
}

func (j *JA4Fingerprint) unmarshalSignatureAlgorithm(chs *utls.ClientHelloSpec) {
	var algo []uint16
	for _, e := range chs.Extensions {
		if sae, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			for _, a := range sae.SupportedSignatureAlgorithms {
				algo = append(algo, uint16(a))
			}
		}
	}
	j.SignatureAlgorithms = algo
}

func extensionID(e utls.TLSExtension) (uint16, error) {
	switch e.(type) {
	case *utls.SNIExtension:
		return ja4ExtensionSNI, nil
	case *utls.ALPNExtension:
		return ja4ExtensionALPN, nil
	case *utls.SessionTicketExtension:
		return ja4ExtensionSessionTicket, nil
	case *utls.UtlsPaddingExtension:
		return ja4ExtensionPadding, nil
	case utls.PreSharedKeyExtension:
		return ja4ExtensionPreSharedKey, nil
	}

	// hack utls to allow reading padding extension data below
	if pe, ok := e.(*utls.UtlsPaddingExtension); ok {
		pe.WillPad = true
	}

	l := e.Len()
	if l == 0 {
		return 0, fmt.Errorf("extension data should not be empty")
	}

	buf := make([]byte, l)
	n, err := e.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("failed to read extension: %w", err)
	}

	if n < 2 {
		return 0, fmt.Errorf("extension data is too short, expect more than 2, actual %d", n)
	}

	return uint16(buf[0])<<8 | uint16(buf[1]), nil
}

func isEphemeralExtension(extensionID uint16) bool {
	switch extensionID {
	case ja4ExtensionPadding, ja4ExtensionSessionTicket, ja4ExtensionPreSharedKey:
		return true
	default:
		return false
	}
}
