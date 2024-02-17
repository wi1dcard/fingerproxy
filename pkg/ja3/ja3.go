/*
 * JA3 - TLS Client Hello Hash
 * Copyright (c) 2017, Salesforce.com, Inc.
 * this code was created by Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ja3

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/dreadl0ck/tlsx"
)

var (
	// Debug indicates whether we run in debug mode.
	Debug        = false
	sepValueByte = byte(45)
	sepFieldByte = byte(44)

	// Ciphers, extensions and elliptic curves, should be filtered so GREASE values are not added to the ja3 digest
	// GREASE RFC: https://tools.ietf.org/html/draft-davidben-tls-grease-01
	greaseValues = map[uint16]bool{
		0x0a0a: true, 0x1a1a: true,
		0x2a2a: true, 0x3a3a: true,
		0x4a4a: true, 0x5a5a: true,
		0x6a6a: true, 0x7a7a: true,
		0x8a8a: true, 0x9a9a: true,
		0xaaaa: true, 0xbaba: true,
		0xcaca: true, 0xdada: true,
		0xeaea: true, 0xfafa: true,
	}
)

// BareToDigestHex converts a bare []byte to a hex string.
func BareToDigestHex(bare []byte) string {
	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// Digest returns only the digest md5.
func Digest(hello *tlsx.ClientHelloBasic) [md5.Size]byte {
	return md5.Sum(Bare(hello))
}

// DigestHex produce md5 hash from bare string.
func DigestHex(hello *tlsx.ClientHelloBasic) string {
	return BareToDigestHex(Bare(hello))
}

// Bare returns the JA3 bare string for a given tlsx.ClientHelloBasic instance
// JA3 is a technique developed by Salesforce, to fingerprint TLS Client Hellos.
// the official python implementation can be found here: https://github.com/salesforce/ja3
// JA3 gathers the decimal values of the bytes for the following fields; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats.
// It then concatenates those values together in order, using a “,” to delimit each field and a “-” to delimit each value in each field.
// The field order is as follows:
// SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// Example:
// 769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0
// If there are no SSL Extensions in the Client Hello, the fields are left empty.
// Example:
// 769,4–5–10–9–100–98–3–6–19–18–99,,,
// These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint.
// This is the JA3 SSL Client Fingerprint returned by this function.
func Bare(hello *tlsx.ClientHelloBasic) []byte {

	// TODO: refactor into struct with inbuilt buffer to reduce allocations to ~ zero
	// i.e. only realloc if previously allocated buffer is too small for current packet

	var (
		maxPossibleBufferLength = 5 + 1 + // Version = uint16 => maximum = 65536 = 5chars + 1 field sep
			(5+1)*len(hello.CipherSuites) + // CipherSuite = uint16 => maximum = 65536 = 5chars
			(5+1)*len(hello.AllExtensions) + // uint16 = 2B => maximum = 65536 = 5chars
			(5+1)*len(hello.SupportedGroups) + // uint16 = 2B => maximum = 65536 = 5chars
			(3+1)*len(hello.SupportedPoints) // uint8 = 1B => maximum = 256 = 3chars

		buffer = make([]byte, 0, maxPossibleBufferLength)
	)

	buffer = strconv.AppendInt(buffer, int64(hello.HandshakeVersion), 10)
	buffer = append(buffer, sepFieldByte)

	/*
	 *	Cipher Suites
	 */

	// collect cipher suites
	lastElem := len(hello.CipherSuites) - 1
	if len(hello.CipherSuites) > 1 {
		for _, e := range hello.CipherSuites[:lastElem] {
			// filter GREASE values
			if !greaseValues[uint16(e)] {
				buffer = strconv.AppendInt(buffer, int64(e), 10)
				buffer = append(buffer, sepValueByte)
			}
		}
	}
	// append last element if cipher suites are not empty
	if lastElem != -1 {
		// filter GREASE values
		if !greaseValues[uint16(hello.CipherSuites[lastElem])] {
			buffer = strconv.AppendInt(buffer, int64(hello.CipherSuites[lastElem]), 10)
		}
	}
	buffer = bytes.TrimSuffix(buffer, []byte{sepValueByte})
	buffer = append(buffer, sepFieldByte)

	/*
	 *	Extensions
	 */

	// collect extensions
	lastElem = len(hello.AllExtensions) - 1
	if len(hello.AllExtensions) > 1 {
		for _, e := range hello.AllExtensions[:lastElem] {
			// filter GREASE values
			if !greaseValues[uint16(e)] {
				buffer = strconv.AppendInt(buffer, int64(e), 10)
				buffer = append(buffer, sepValueByte)
			}
		}
	}
	// append last element if extensions are not empty
	if lastElem != -1 {
		// filter GREASE values
		if !greaseValues[uint16(hello.AllExtensions[lastElem])] {
			buffer = strconv.AppendInt(buffer, int64(hello.AllExtensions[lastElem]), 10)
		}
	}
	buffer = bytes.TrimSuffix(buffer, []byte{sepValueByte})
	buffer = append(buffer, sepFieldByte)

	/*
	 *	Supported Groups
	 */

	// collect supported groups
	lastElem = len(hello.SupportedGroups) - 1
	if len(hello.SupportedGroups) > 1 {
		for _, e := range hello.SupportedGroups[:lastElem] {
			// filter GREASE values
			if !greaseValues[uint16(e)] {
				buffer = strconv.AppendInt(buffer, int64(e), 10)
				buffer = append(buffer, sepValueByte)
			}
		}
	}
	// append last element if supported groups are not empty
	if lastElem != -1 {
		// filter GREASE values
		if !greaseValues[uint16(hello.SupportedGroups[lastElem])] {
			buffer = strconv.AppendInt(buffer, int64(hello.SupportedGroups[lastElem]), 10)
		}
	}
	buffer = bytes.TrimSuffix(buffer, []byte{sepValueByte})
	buffer = append(buffer, sepFieldByte)

	/*
	 *	Supported Points
	 */

	// collect supported points
	lastElem = len(hello.SupportedPoints) - 1
	if len(hello.SupportedPoints) > 1 {
		for _, e := range hello.SupportedPoints[:lastElem] {
			buffer = strconv.AppendInt(buffer, int64(e), 10)
			buffer = append(buffer, sepValueByte)
		}
	}
	// append last element if supported points are not empty
	if lastElem != -1 {
		buffer = strconv.AppendInt(buffer, int64(hello.SupportedPoints[lastElem]), 10)
	}

	return buffer
}
