package main

import (
	"context"
	"flag"

	"github.com/aredoff/ja4t"
)

func main() {
	device := flag.String("device", "", "Device to listen on")
	flag.Parse()

	j := ja4t.New()
	if *device != "" {
		j.SetDevice(*device)
	}

	c, err := j.Listen(context.Background())
	if err != nil {
		println(err.Error())
		return
	}

	for p := range c {
		println(p.String())
	}

}
