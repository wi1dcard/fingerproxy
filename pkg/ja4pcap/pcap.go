package ja4pcap

import (
	"errors"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
)

type clientHelloPacket struct {
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint16 `json:"destination_port"`
	SourceIP        string `json:"source_ip"`
	SourcePort      uint16 `json:"source_port"`
	JA4             string `json:"ja4"`
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

func Hello() {

}

// returns ("", nil) if p is not a ClientHello
func ja4FromPacket(p gopacket.Packet) (string, error) {
	tl := p.TransportLayer()
	if tl == nil {
		return "", nil
	}

	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", nil
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp.SYN || tcp.FIN || tcp.RST {
		return "", nil
	}

	pl := tcp.LayerPayload()
	if len(pl) == 0 {
		return "", nil
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
			return "", nil
		case "handshake message is not a ClientHello":
			return "", nil
		case "unable to read record type, version, and length":
			return "", nil
		case "unable to read handshake message type, length, and random":
			return "", nil
		// otherwise returns error
		default:
			return "", err
		}
	}

	return j.String(), nil
}

func ReadFileJSON2(file string) []*clientHelloPacket {
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	packetDataSource, linkType := openPcap(f)
	packetSource := gopacket.NewPacketSource(packetDataSource, linkType)

	var packets []*clientHelloPacket

	for p := range packetSource.Packets() {
		chp := &clientHelloPacket{}

		chp.JA4, err = ja4FromPacket(p)
		if err != nil {
			panic(err)
		}
		// packet is not a ClientHello
		if chp.JA4 == "" {
			continue
		}

		ipv4Layer := p.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			chp.DestinationIP = ip.DstIP.String()
			chp.SourceIP = ip.SrcIP.String()
		}

		ipv6Layer := p.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			chp.DestinationIP = ip.DstIP.String()
			chp.SourceIP = ip.SrcIP.String()
		}

		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			chp.DestinationPort = uint16(tcp.DstPort)
			chp.SourcePort = uint16(tcp.SrcPort)
		}

		packets = append(packets, chp)
	}

	return packets
}
