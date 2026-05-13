package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"github.com/ret2ntr/gpwntools"
)

func main() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to locate demo source path")
	}
	target := filepath.Join(filepath.Dir(file), "target", "test")

	p, err := gpwntools.Process(target)
	if err != nil {
		panic(err)
	}
	defer p.Close()

	banner, err := p.RecvUntil([]byte("\n"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("recvuntil: %s", banner)

	if err := p.Send([]byte("AAAA\n")); err != nil {
		panic(err)
	}
	_ = p.Wait()
}
