package ja4t

import (
	"context"
	"errors"

	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const BPFFilter = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & tcp-ack == 0"

func New() *listener {
	return &listener{
		// buffer: make(chan SynInfo, 100),
	}
}

type SynInfo interface {
	JA4T() JA4T
	String() string
	ToSlice() []string
	MarshalJSON() ([]byte, error)
}

type listener struct {
	filter *filter
}

func (l *listener) SetFilter(f *filter) {
	l.filter = f
}

func (l *listener) Listen(ctx context.Context, device string) (chan SynInfo, error) {
	var err error

	buffer := make(chan SynInfo, 100)

	if device == "" {
		return nil, errors.New("device is not set")
	}
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter(BPFFilter)
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
				close(buffer)
				return
			case packet, ok := <-packetsChannel:
				if !ok {
					close(buffer)
					return
				}

				i, err := getSynInfo(packet)
				if err != nil {
					log.Println(err)
					continue
				}
				if l.filter != nil {
					if l.filter.Match(i) {
						buffer <- i
					}
				} else {
					buffer <- i
				}
			}
		}
	}()
	return buffer, nil
}
