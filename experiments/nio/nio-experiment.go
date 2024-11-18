package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/djherbis/buffer"
	"github.com/djherbis/nio/v3"
)

func Main() error {
	buf := buffer.New(1 << 15) // 32 KB buffer
	r, w := nio.Pipe(buf)

	// start reading in background every 1 second
	go func() {
		buf := make([]byte, 12)
		for range time.Tick(1 * time.Second) {
			n, err := r.Read(buf)
			if err != nil {
				break
			}
			log.Printf("read: %q", string(buf[:n]))
		}
	}()

	// write every 5 seconds
	var i int
	for range time.Tick(2 * time.Second) {
		log.Println("about to write...")
		begin := time.Now()
		fmt.Fprintf(w, "hello nio %d "+strings.Repeat("=", 50), i)
		log.Printf("finished write in %v", time.Since(begin))
		i++
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}
