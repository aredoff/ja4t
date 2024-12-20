package ja4t

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Test() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	a := map[string]uint64{}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		i := getSynInfo(packet)
		j := i.JA4T()
		if _, ok := a[j.String()]; ok {

			a[j.String()]++
		} else {
			a[j.String()] = 1
		}
		fmt.Println(i.String() + "  " + fmt.Sprint(a[j.String()]))
	}
}
