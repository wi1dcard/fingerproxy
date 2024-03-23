package ja4pcap

import (
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

type snap struct {
	Stream    int
	Ja4       string
	Transport string
	Src       string
	Dst       string
	SrcPort   uint16 `yaml:"src_port"`
	DstPort   uint16 `yaml:"dst_port"`
}

func TestRead(t *testing.T) {

	entries, err := os.ReadDir("testdata/pcap/")
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		t.Run(e.Name(), func(t *testing.T) {
			rs := ReadFileJSON2("testdata/pcap/" + e.Name())
			snapFile := fmt.Sprintf("testdata/snapshots/ja4__insta@%s.snap", e.Name())

			snapFileBytes, err := os.Open(snapFile)
			if err != nil {
				t.Fatal(err)
			}
			defer snapFileBytes.Close()

			theSnap := &[]snap{}
			decoder := yaml.NewDecoder(snapFileBytes)
			var s struct{}
			decoder.Decode(&s)
			decoder.Decode(theSnap)

			i := 0
			t.Log("len: ", len(rs))
			for _, v := range *theSnap {
				if v.Ja4 != "" && v.Transport != "udp" {
					t.Log(v.Dst, v.DstPort, v.Src, v.SrcPort)
					t.Log(rs[i].DestinationIP, rs[i].DestinationPort, rs[i].SourceIP, rs[i].SourcePort)
					t.Log(v.Ja4, rs[i].JA4)
					if v.Ja4 != rs[i].JA4 {
						t.Fatal("fail")
					}
					i++
				}
			}

			// t.Log(theSnap)
		})

	}

}
