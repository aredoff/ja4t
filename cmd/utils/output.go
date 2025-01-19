package utils

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"
)

const (
	defaultMaxBufferSize = 8 * 1024
	defaultResetTime     = 2 * time.Second
)

func NewOutput(ctx context.Context, w io.Writer) *output {
	o := output{
		output:     w,
		resetTime:  defaultResetTime,
		maxBufSize: defaultMaxBufferSize,
		err:        make(chan error),
		mu:         &sync.Mutex{},
	}
	go o.FlushTimer(ctx, defaultResetTime)
	return &o
}

type output struct {
	buf        bytes.Buffer
	resetTime  time.Duration
	maxBufSize int

	lastFlashed time.Time
	err         chan error
	output      io.Writer
	mu          *sync.Mutex
}

func (o *output) Write(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf.Write(p)
	if o.buf.Len() > o.maxBufSize {
		go o.flush(o.buf.Bytes())
		o.buf.Reset()
		o.lastFlashed = time.Now()
	}
}

func (o *output) FlushTimer(ctx context.Context, d time.Duration) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.mu.Lock()
			if o.buf.Len() > 0 {
				go o.flush(o.buf.Bytes())
				o.buf.Reset()
				o.lastFlashed = time.Now()
			}
			o.mu.Unlock()
		}
	}
}

func (o *output) flush(data []byte) {
	_, err := o.output.Write(data)
	if err != nil {
		o.err <- err
	}
}
func (o *output) Error() <-chan error {
	return o.err
}
