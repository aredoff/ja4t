package ja4t

import (
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const filter = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & tcp-ack == 0"

func New() *listener {
	return &listener{
		// buffer: make(chan SynInfo, 100),
	}
}

type SynInfo interface {
	JA4T() JA4T
	String() string
}

type listener struct {
	device string
}

func (l *listener) SetDevice(device string) {
	l.device = device
}

// func (l *listener) Packets() chan SynInfo {
// 	return l.buffer
// }

func (l *listener) Listen(ctx context.Context) (chan SynInfo, error) {
	buffer := make(chan SynInfo, 100)
	var err error
	if l.device == "" {
		l.device, err = findInterface()
		if err != nil {
			return nil, err
		}
	}
	handle, err := pcap.OpenLive(l.device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packetsChannel := packetSource.Packets()

	go func() {
		defer handle.Close()
		for {
			select {
			case <-ctx.Done():
				fmt.Println("context done")
				close(buffer)
				return
			case packet, ok := <-packetsChannel:
				if !ok {
					fmt.Println("packetsChannel closed")
					close(buffer)
					return
				}
				i := getSynInfo(packet)
				buffer <- i
			}
		}
	}()
	return buffer, nil
}

func findInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.IsLoopback() {
				break
			}
			return iface.Name, nil
		}
	}
	return "", nil
}
