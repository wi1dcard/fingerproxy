package ja4

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestStableJA4CollapsesChromePSKVariant(t *testing.T) {
	fullHandshake, err := utls.UTLSIdToSpec(utls.HelloChrome_100)
	if err != nil {
		t.Fatal(err)
	}

	resumedHandshake, err := utls.UTLSIdToSpec(utls.HelloChrome_100_PSK)
	if err != nil {
		t.Fatal(err)
	}

	rawFull := mustRawJA4FromSpec(t, &fullHandshake)
	rawResumed := mustRawJA4FromSpec(t, &resumedHandshake)
	stableFull := mustStableJA4FromSpec(t, &fullHandshake)
	stableResumed := mustStableJA4FromSpec(t, &resumedHandshake)

	if rawFull == rawResumed {
		t.Fatalf("expected raw JA4 to drift, got %s and %s", rawFull, rawResumed)
	}
	if stableFull != stableResumed {
		t.Fatalf("expected stable JA4 to collapse variants, got %s and %s", stableFull, stableResumed)
	}
}

func TestStableJA4IgnoresEphemeralExtensions(t *testing.T) {
	testCases := []struct {
		name      string
		extension utls.TLSExtension
	}{
		{
			name: "session-ticket",
			extension: &utls.SessionTicketExtension{
				Ticket: []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "padding",
			extension: &utls.UtlsPaddingExtension{
				WillPad:    true,
				PaddingLen: 8,
			},
		},
		{
			name: "pre-shared-key",
			extension: &utls.FakePreSharedKeyExtension{
				Identities: []utls.PskIdentity{{
					Label:               []byte("ticket"),
					ObfuscatedTicketAge: 1,
				}},
				Binders: [][]byte{make([]byte, 32)},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			baseSpec := testJA4BaseSpec()
			variantSpec := testJA4BaseSpec()
			variantSpec.Extensions = append(variantSpec.Extensions, tc.extension)

			baseRaw := mustRawJA4FromSpec(t, baseSpec)
			variantRaw := mustRawJA4FromSpec(t, variantSpec)
			baseStable := mustStableJA4FromSpec(t, baseSpec)
			variantStable := mustStableJA4FromSpec(t, variantSpec)

			if baseRaw == variantRaw {
				t.Fatalf("expected raw JA4 to change for %s", tc.name)
			}
			if baseStable != variantStable {
				t.Fatalf("expected stable JA4 to ignore %s: %s != %s", tc.name, baseStable, variantStable)
			}
		})
	}
}

func TestStableJA4StillChangesForNonEphemeralExtensions(t *testing.T) {
	baseSpec := testJA4BaseSpec()
	variantSpec := testJA4BaseSpec()
	variantSpec.Extensions = append(variantSpec.Extensions, &utls.StatusRequestExtension{})

	baseStable := mustStableJA4FromSpec(t, baseSpec)
	variantStable := mustStableJA4FromSpec(t, variantSpec)

	if baseStable == variantStable {
		t.Fatalf("expected stable JA4 to change for non-ephemeral extensions")
	}
}

func mustRawJA4FromSpec(t *testing.T, spec *utls.ClientHelloSpec) string {
	t.Helper()

	fp := &JA4Fingerprint{}
	if err := fp.Unmarshal(spec, 't'); err != nil {
		t.Fatal(err)
	}
	return fp.String()
}

func mustStableJA4FromSpec(t *testing.T, spec *utls.ClientHelloSpec) string {
	t.Helper()

	fp := &StableJA4Fingerprint{}
	if err := fp.Unmarshal(spec, 't'); err != nil {
		t.Fatal(err)
	}
	return fp.String()
}

func testJA4BaseSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "example.com"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
			}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{
				Group: utls.X25519,
				Data:  []byte{0x01, 0x02, 0x03, 0x04},
			}}},
		},
	}
}
