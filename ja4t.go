package ja4t

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/gopacket/layers"
)

func newJA4T(tcp *layers.TCP) JA4T {
	ja4t := JA4T{
		WindowSize: tcp.Window,
	}

	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				ja4t.MaximumSegmentSize = uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				ja4t.WindowScale = opt.OptionData[0]
			}
		default:
			ja4t.Options = append(ja4t.Options, uint8(opt.OptionType))
		}
	}

	sort.Slice(ja4t.Options, func(i, j int) bool { return ja4t.Options[i] < ja4t.Options[j] })

	return ja4t
}

type JA4T struct {
	WindowSize         uint16
	Options            []uint8
	MaximumSegmentSize uint16
	WindowScale        uint8
}

func (JA4T *JA4T) String() string {
	options := make([]string, len(JA4T.Options))
	for i, o := range JA4T.Options {
		options[i] = fmt.Sprintf("%v", o)
	}
	return fmt.Sprintf("%v_%v_%v_%v", JA4T.WindowSize, strings.Join(options, "-"), JA4T.MaximumSegmentSize, JA4T.WindowScale)
}
