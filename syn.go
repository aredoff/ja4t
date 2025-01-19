package ja4t

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	Fields = []string{"src_ip", "src_port", "dst_ip", "dst_port", "ja4t"}
)

func getSynInfo(packet gopacket.Packet) (synInfo, error) {
	synInfo := synInfo{
		DT: time.Now(),
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return synInfo, fmt.Errorf("Failed to cast to IP layer")
		}
		synInfo.SrcIP = ip.SrcIP
		synInfo.DstIP = ip.DstIP
	} else {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer != nil {
			ip, ok := ipLayer.(*layers.IPv6)
			if !ok {
				return synInfo, fmt.Errorf("Failed to cast to layers.IPv6 ")
			}
			synInfo.SrcIP = ip.SrcIP
			synInfo.DstIP = ip.DstIP
		} else {
			return synInfo, fmt.Errorf("Failed to cast to IP layer")
		}
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return synInfo, fmt.Errorf("Failed to cast to TCP layer")
		}
		synInfo.ja4t = newJA4T(tcp)
		synInfo.SrcPort = uint16(tcp.SrcPort)
		synInfo.DstPort = uint16(tcp.DstPort)
		// fmt.Printf("JA4T: %+v\n", ja4t)
		// fmt.Printf("TCP Port %d -> %d SYN\n", tcp.SrcPort, tcp.DstPort)
	}
	return synInfo, nil
}

type synInfo struct {
	DT      time.Time
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16

	ja4t JA4T
}

func (s synInfo) JA4T() JA4T {
	return s.ja4t
}

func (s synInfo) String() string {
	return fmt.Sprintf("[%s] %s:%d - %s:%d: %s", s.DT.Format("2006-01-02 15:04:05"), s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.ja4t.String())
}

func (s synInfo) ToSlice() []string {
	return []string{s.DT.Format("2006-01-02 15:04:05"), s.SrcIP.String(), fmt.Sprintf("%d", s.SrcPort), s.DstIP.String(), fmt.Sprintf("%d", s.DstPort), s.ja4t.String()}
}

func (s synInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		DT      string `json:"dt"`
		SrcIP   string `json:"src_ip"`
		DstIP   string `json:"dst_ip"`
		SrcPort uint16 `json:"src_port"`
		DstPort uint16 `json:"dst_port"`
		JA4T    string `json:"ja4t"`
	}{
		DT:      s.DT.Format("2006-01-02 15:04:05"),
		SrcIP:   s.SrcIP.String(),
		DstIP:   s.DstIP.String(),
		SrcPort: s.SrcPort,
		DstPort: s.DstPort,
		JA4T:    s.ja4t.String(),
	})
}
