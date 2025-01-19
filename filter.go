package ja4t

import (
	"log"

	"github.com/kor44/gofilter"
)

func CreateFilter(rule string) (*filter, error) {
	f, err := gofilter.NewFilter(rule)
	if err != nil {
		return nil, err
	}
	return &filter{f: f}, nil
}

type filter struct {
	f *gofilter.Filter
}

func (f *filter) Match(i synInfo) bool {
	message := gofilter.Message{
		"ip.src":      i.SrcIP,
		"tcp.dstport": i.DstPort,
		"ip.dst":      i.DstIP,
		"tcp.srcport": i.SrcPort,
		"tls.ja4t":    i.ja4t.String(),
	}
	return f.f.Apply(message)
}

func init() {
	var err error

	err = gofilter.RegisterField("ip.src", gofilter.FT_IP)
	if err != nil {
		log.Panic(err)
	}

	err = gofilter.RegisterField("tcp.dstport", gofilter.FT_UINT16)
	if err != nil {
		log.Panic(err)
	}

	err = gofilter.RegisterField("ip.dst", gofilter.FT_IP)
	if err != nil {
		log.Panic(err)
	}

	err = gofilter.RegisterField("tcp.srcport", gofilter.FT_UINT16)
	if err != nil {
		log.Panic(err)
	}

	err = gofilter.RegisterField("tls.ja4t", gofilter.FT_STRING)
	if err != nil {
		log.Panic(err)
	}
}
