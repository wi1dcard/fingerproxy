package main

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/dreadl0ck/tlsx"
	"github.com/wi1dcard/fingerproxy"
	"github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/ja3"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
	"github.com/wi1dcard/fingerproxy/pkg/reverseproxy"
)

func main() {
	fingerproxy.GetHeaderInjectors = func() []reverseproxy.HeaderInjector {
		i := fingerproxy.DefaultHeaderInjectors()
		i = append(i, fingerprint.NewFingerprintHeaderInjector(
			"X-Sorted-JA3-Fingerprint",
			fpSortedJA3,
		))
		return i
	}
	fingerproxy.Run()
}

func fpSortedJA3(data *metadata.Metadata) (string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(data.ClientHelloRecord); err != nil {
		return "", fmt.Errorf("ja3: %w", err)
	}

	fp := string(ja3.Bare(hellobasic))

	fields := strings.Split(fp, ",")
	if len(fields) != 5 {
		// here should be impossible
		return "", fmt.Errorf("bad ja3 fingerprint")
	}

	extensions := strings.Split(fields[2], "-")
	if len(extensions) == 0 {
		// no tls extension
		return ja3.BareToDigestHex([]byte(fp)), nil
	}

	// very ugly implementations for demonstration purpose only
	slices.SortFunc(extensions, func(x string, y string) int {
		var _x, _y int
		var err error
		if _x, err = strconv.Atoi(x); err != nil {
			return 0
		}
		if _y, err = strconv.Atoi(y); err != nil {
			return 0
		}
		return cmp.Compare(_x, _y)
	})

	fields[2] = strings.Join(extensions, "-")
	fp = strings.Join(fields, ",")

	// return fp, nil
	return ja3.BareToDigestHex([]byte(fp)), nil
}
