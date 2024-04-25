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

func (j *JA4Fingerprint) UnmarshalBytes(clientHelloRecord []byte, protocol byte) error {
	chs := &utls.ClientHelloSpec{}
	// allowBluntMimicry: true
	// realPSK: false
	err := chs.FromRaw(clientHelloRecord, true, false)
	if err != nil {
		return fmt.Errorf("cannot parse client hello: %w", err)
	}
	return j.Unmarshal(chs, protocol)
}

func (j *JA4Fingerprint) Unmarshal(chs *utls.ClientHelloSpec, protocol byte) error {
	var err error

	// ja4_a
	j.Protocol = protocol
	j.unmarshalTLSVersion(chs)
	j.unmarshalSNI(chs)
	j.unmarshalNumberOfCipherSuites(chs)
	j.unmarshalNumberOfExtensions(chs)
	j.unmarshalFirstALPN(chs)

	// ja4_b
	j.unmarshalCipherSuites(chs, false)

	// ja4_c
	err = j.unmarshalExtensions(chs, false)
	if err != nil {
		return err
	}
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

func (j *JA4Fingerprint) unmarshalNumberOfExtensions(chs *utls.ClientHelloSpec) {
	var n int
	for _, e := range chs.Extensions {
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			continue
		}
		n++
	}
	j.NumberOfExtensions = numberOfExtensions(n)
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
func (j *JA4Fingerprint) unmarshalExtensions(chs *utls.ClientHelloSpec, keepOriginalOrder bool) error {
	var extensions []uint16
	for _, e := range chs.Extensions {
		// exclude GREASE extensions
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			continue
		}

		if !keepOriginalOrder {
			// SNI and ALPN extension should not be included, ref:
			// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L79
			if _, ok := e.(*utls.SNIExtension); ok {
				continue
			}
			if _, ok := e.(*utls.ALPNExtension); ok {
				continue
			}
		}

		// hack utls to allow reading padding extension data below
		if pe, ok := e.(*utls.UtlsPaddingExtension); ok {
			pe.WillPad = true
		}

		l := e.Len()
		if l == 0 {
			return fmt.Errorf("extension data should not be empty")
		}

		buf := make([]byte, l)
		n, err := e.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read extension: %w", err)
		}

		if n < 2 {
			return fmt.Errorf("extension data is too short, expect more than 2, actual %d", n)
		}
		extId := uint16(buf[0])<<8 | uint16(buf[1])

		extensions = append(extensions, extId)
	}

	if !keepOriginalOrder {
		sortUint16(extensions)
	}
	j.Extensions = extensions
	return nil
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
