package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aredoff/ja4t"
	"github.com/aredoff/ja4t/cmd/utils"
)

const (
	outputFormatConsole uint16 = iota
	outputFormatCSV
	outputFormatJSON
)

var (
	deviceFlag = flag.String("device", "", "Network device to listen on (e.g., eth0, wlan0)")
	filterFlag = flag.String("filter", "", `Packet filter expression (e.g., "ip.dst == 178.172.160.93 and tcp.dstport == 8123")

Variables: 
ip.src - Source IP address
tcp.dstport - Destination TCP port
ip.dst - Destination IP address
tcp.srcport - Source TCP port
tls.ja4t - JA4t string fingerprint of the TLS connection

Comparison operators:
and, &&   Logical AND
or,  ||   Logical OR
not, !    Logical NOT

eq, ==    Equal
ne, !=    Not Equal
gt, >     Greater Than
lt, <     Less Than
ge, >=    Greater than or Equal to
le, <=    Less than or Equal to

Search and match operators:
contains  Does the protocol, field or slice contain a value
matches   Does the protocol or text string match the given Perl
          regular expression`)
	csvFlag        = flag.Bool("csv", false, "Output results in CSV format")
	jsonFlag       = flag.Bool("json", false, "Output results in JSON format")
	outputFileFlag = flag.String("output", "", "File to write output to (leave empty for stdout)")
)

func main() {
	flag.Parse()

	// fmt.Println(*deviceFlag, *filterFlag, *csvFlag, *outputFileFlag, *jsonFlag)

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	var device string
	if *deviceFlag == "" {
		deviceFind, err := utils.FindInterface()
		if err != nil {
			fmt.Println("Error finding network device:", err)
			return
		}
		device = deviceFind
	} else {
		device = *deviceFlag
	}

	j := ja4t.New()

	if *filterFlag != "" {
		f, err := ja4t.CreateFilter(*filterFlag)
		if err != nil {
			fmt.Println("Error creating filter:", err)
			return
		}
		j.SetFilter(f)
	}

	c, err := j.Listen(ctx, device)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}

	var output io.WriteCloser

	if *outputFileFlag == "" {
		output = os.Stdout
	} else {
		var err error
		output, err = os.Create(*outputFileFlag)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			return
		}
		defer output.Close()
	}

	buffer := utils.NewOutput(ctx, output)

	outputFormat := outputFormatConsole
	if *csvFlag {
		outputFormat = outputFormatCSV
	}
	if *jsonFlag {
		outputFormat = outputFormatJSON
	}

	go func() {
		for {
			select {
			case <-exit:
				cancel()
			case err := <-buffer.Error():
				fmt.Println("Error writing to output:", err)
				cancel()
			case s, ok := <-c:
				if !ok {
					cancel()
					return
				}

				switch outputFormat {
				case outputFormatCSV:
					buffer.Write([]byte(strings.Join(s.ToSlice(), ",") + "\n"))
				case outputFormatJSON:
					jsonBytes, _ := s.MarshalJSON()
					buffer.Write(append(jsonBytes, '\n'))
				default:
					buffer.Write([]byte(s.String() + "\n"))
				}
			}
		}
	}()
	<-ctx.Done()
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println("This utility intercepts SYN packets and collects JA4t fingerprints.")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
	}
}
