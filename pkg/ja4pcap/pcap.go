package ja4pcap

import (
	"errors"
	"io"
	"os"
	"slices"

	"cmp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
)

type pcapClientHello struct {
	tcpStreamTuple
	StreamIndex int
	JA4         string
}

type tcpStreamTuple struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// returns true if either:
// a) t1.src == t2.src and t1.dst == t2.dst
// b) t1.src == t2.dst and t1.dst == t2.src
func (t1 *tcpStreamTuple) Equal(t2 tcpStreamTuple) bool {
	// match tuple [address A + port A, address B + port B]
	if t1.DstIP == t2.DstIP && t1.DstPort == t2.DstPort &&
		t1.SrcIP == t2.SrcIP && t1.SrcPort == t2.SrcPort {
		return true
	}
	if t1.DstIP == t2.SrcIP && t1.DstPort == t2.SrcPort &&
		t1.SrcIP == t2.DstIP && t1.SrcPort == t2.DstPort {
		return true
	}
	return false
}

func openPcap(f *os.File) (gopacket.PacketDataSource, layers.LinkType) {
	pcapReader, errPcap := pcapgo.NewReader(f)
	if errPcap == nil {
		return pcapReader, pcapReader.LinkType()
	}

	f.Seek(0, io.SeekStart)
	ngReader, errPcapNg := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if errPcapNg != nil {
		panic(errPcapNg)
	}

	return ngReader, ngReader.LinkType()
}

var errPacketIsNotClientHello = errors.New("packet is not a client hello")

func ja4FromPacket(tcp *layers.TCP) (string, error) {
	if tcp.SYN || tcp.FIN || tcp.RST {
		return "", errPacketIsNotClientHello
	}

	pl := tcp.LayerPayload()
	if len(pl) == 0 {
		return "", errPacketIsNotClientHello
	}

	j := ja4.JA4Fingerprint{}
	err := j.UnmarshalBytes(pl, 't')
	if err != nil {
		if ie := errors.Unwrap(err); ie != nil {
			err = ie
		}
		switch err.Error() {
		// utls cannot parse the ClientHello
		case "record is not a handshake":
			return "", errPacketIsNotClientHello
		case "handshake message is not a ClientHello":
			return "", errPacketIsNotClientHello
		case "unable to read record type, version, and length":
			return "", errPacketIsNotClientHello
		case "unable to read handshake message type, length, and random":
			return "", errPacketIsNotClientHello
		// otherwise returns error
		default:
			return "", err
		}
	}

	return j.String(), nil
}

func readPcap(file string) []pcapClientHello {
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	packetDataSource, linkType := openPcap(f)
	packetSource := gopacket.NewPacketSource(packetDataSource, linkType)

	var clientHellos []pcapClientHello
	var tcpStreams []tcpStreamTuple

	for p := range packetSource.Packets() {
		ch := pcapClientHello{}
		srcdst := tcpStreamTuple{}

		if ipv4Layer := p.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			srcdst.DstIP = ip.DstIP.String()
			srcdst.SrcIP = ip.SrcIP.String()
		} else if ipv6Layer := p.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			srcdst.DstIP = ip.DstIP.String()
			srcdst.SrcIP = ip.SrcIP.String()
		} else {
			// not IPv4 or IPv6
			continue
		}

		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			// not TCP
			continue
		}

		tcp, _ := tcpLayer.(*layers.TCP)
		srcdst.DstPort = uint16(tcp.DstPort)
		srcdst.SrcPort = uint16(tcp.SrcPort)

		// get wireshark stream index before parsing JA4
		ch.StreamIndex = slices.IndexFunc(tcpStreams, srcdst.Equal)
		if ch.StreamIndex == -1 {
			ch.StreamIndex = len(tcpStreams)
			tcpStreams = append(tcpStreams, srcdst)
		}

		ch.JA4, err = ja4FromPacket(tcp)
		if err == nil {
			ch.tcpStreamTuple = srcdst
			clientHellos = append(clientHellos, ch)
		} else if !errors.Is(err, errPacketIsNotClientHello) {
			panic(err)
		}
	}

	// sort by stream index
	slices.SortFunc(clientHellos, func(x pcapClientHello, y pcapClientHello) int {
		return cmp.Compare(x.StreamIndex, y.StreamIndex)
	})

	return clientHellos
}
