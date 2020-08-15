package main

import (
	"bytes"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
	"io"
	"log"
	"math/rand"
	"time"
)

var (
	small  = make([]byte, 1024)
	medium = make([]byte, 17*1024)
	large  = make([]byte, 3*1024*1024)
	xlarge = make([]byte, 533*1024*1024)
)

func fill(b []byte) {
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
}

func bench(kh *keyset.Handle, src []byte) time.Duration {
	s, err := streamingaead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	dest := bytes.Buffer{}
	dest.Grow(len(src) * 2)

	reader := bytes.NewReader(src)
	writer, err := s.NewEncryptingWriter(&dest, nil)
	if err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	_, err = io.Copy(writer, reader)
	stop := time.Now()

	if err != nil {
		log.Fatal(err)
	}

	return stop.Sub(start)
}

func main() {
	const count = 60

	targets := [][]byte{small, medium, large, xlarge}

	for _, t := range targets {
		fill(t)
	}

	kh4k, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	for _, t := range targets {
		bench(kh4k, t)
	}

	for _, t := range targets {
		var sum int64
		for i := 0; i < count; i++ {
			sum += bench(kh4k, t).Microseconds()
		}
		log.Printf("4k enc %12d in avg %d us", len(t), sum/count)
	}

	kh1m, err := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	for _, t := range targets {
		bench(kh1m, t)
	}

	for _, t := range targets {
		var sum int64
		for i := 0; i < count; i++ {
			sum += bench(kh1m, t).Microseconds()
		}
		log.Printf("1m enc %12d in avg %d us", len(t), sum/count)
	}

}
