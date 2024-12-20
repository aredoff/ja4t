package ja4t

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func getSynInfo(packet gopacket.Packet) synInfo {
	synInfo := synInfo{}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		synInfo.SrcIP = ip.SrcIP.String()
		synInfo.DstIP = ip.DstIP.String()
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		synInfo.ja4t = newJA4T(tcp)
		synInfo.SrcPort = uint16(tcp.SrcPort)
		synInfo.DstPort = uint16(tcp.DstPort)
		// fmt.Printf("JA4T: %+v\n", ja4t)
		// fmt.Printf("TCP Port %d -> %d SYN\n", tcp.SrcPort, tcp.DstPort)
	}
	return synInfo
}

type synInfo struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16

	ja4t JA4T
}

func (s synInfo) JA4T() JA4T {
	return s.ja4t
}

func (s synInfo) String() string {
	return fmt.Sprintf("%s:%d - %s:%d: %s", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.ja4t.String())
}
