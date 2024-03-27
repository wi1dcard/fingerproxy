package ja4pcap

import (
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

type snap struct {
	StreamIndex int    `yaml:"stream"`
	Transport   string `yaml:"transport"`

	SrcIP   string `yaml:"src"`
	SrcPort uint16 `yaml:"src_port"`
	DstIP   string `yaml:"dst"`
	DstPort uint16 `yaml:"dst_port"`

	JA4 string `yaml:"ja4"`
}

func TestPcap(t *testing.T) {
	pcapFiles, err := os.ReadDir("testdata/pcap/")
	if err != nil {
		t.Fatal(err)
	}

	for _, pf := range pcapFiles {
		if pf.IsDir() {
			continue
		}

		t.Run(pf.Name(), func(t *testing.T) {
			clientHellos := readPcap("testdata/pcap/" + pf.Name())
			snapFilename := fmt.Sprintf("testdata/snapshots/ja4__insta@%s.snap", pf.Name())
			clientHelloSnapshots := readSnapshot(t, snapFilename)

			expLen := len(clientHelloSnapshots)
			if actLen := len(clientHellos); expLen != actLen {
				t.Fatalf("expected %d client hello records, actual %d", expLen, actLen)
			}

			for i := 0; i < expLen; i++ {
				exp := clientHelloSnapshots[i]
				act := clientHellos[i]

				if act.StreamIndex != exp.StreamIndex {
					t.Errorf("expected stream index %d, actual %d", exp.StreamIndex, act.StreamIndex)
				}
				if act.DstIP != exp.DstIP {
					t.Errorf("[%d] expected dst IP %s, actual %s", exp.StreamIndex, exp.DstIP, act.DstIP)
				}
				if act.DstPort != exp.DstPort {
					t.Errorf("[%d] expected dst port %d, actual %d", exp.StreamIndex, exp.DstPort, act.DstPort)
				}
				if act.SrcIP != exp.SrcIP {
					t.Errorf("[%d] expected src IP %s, actual %s", exp.StreamIndex, exp.SrcIP, act.SrcIP)
				}
				if act.SrcPort != exp.SrcPort {
					t.Errorf("[%d] expected src port %d, actual %d", exp.StreamIndex, exp.SrcPort, act.SrcPort)
				}
				if act.JA4 != exp.JA4 {
					t.Errorf("[%d] expected JA4 fingerprint %s, actual %s", exp.StreamIndex, exp.JA4, act.JA4)
				}
			}
		})
	}
}

func readSnapshot(t *testing.T, snapFilename string) []snap {
	t.Helper()

	snapFileBytes, err := os.Open(snapFilename)
	if err != nil {
		t.Fatal(err)
	}
	defer snapFileBytes.Close()

	var (
		snapshots, filteredSnapshots []snap
		unusedFirstYamlDoc           struct{}
	)

	decoder := yaml.NewDecoder(snapFileBytes)
	decoder.Decode(&unusedFirstYamlDoc)
	decoder.Decode(&snapshots)

	for _, sn := range snapshots {
		// udp not supported yet
		if sn.JA4 == "" || sn.Transport == "udp" {
			continue
		}

		filteredSnapshots = append(filteredSnapshots, sn)
	}

	return filteredSnapshots
}
